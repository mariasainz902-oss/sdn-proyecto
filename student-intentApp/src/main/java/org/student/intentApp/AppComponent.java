/*
 * Copyright 2016 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.student.intentApp;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpPrefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * VPN manager: reads the accept/reject state written by the web app and
 * installs (accept) or removes (reject) the OpenFlow rules for each
 * direction of each tunnel.
 *
 * A tunnel only works both ways when BOTH ends have accepted it:
 *   "H1 tunnel1" -> rules H1 -> H2
 *   "H2 tunnel1" -> rules H2 -> H1
 *   "H1 tunnel2" -> rules H1 -> H3
 *   "H3 tunnel2" -> rules H3 -> H1
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = getLogger(getClass());

    // ---- Settings ---------------------------------------------------------

    /** Must match onos.app.name in pom.xml. */
    private static final String APP_NAME = "org.student.intentApp";

    /** File written by the web app. One line per entry: "H1 tunnel1 accept". */
    private static final String STATE_FILE = "/tmp/tunnels.txt";

    private static final int POLL_SECONDS = 2;
    private static final int PRIORITY = 40000;

    // ---- Topology (ADJUST to match the Mininet script) --------------------
    //
    // DPIDs: Mininet assigns s1..s4 -> of:000...1 .. of:000...4 by default.
    // Ports from the Mininet script (assigned in the order of addLink):
    //   S1: 1->H1  2->S3  3->S4
    //   S2: 1->H2  2->S3  3->S4
    //   S3: 1->H3  2->S1  3->S2
    //   S4: 1->S1  2->S2

    private static final Ip4Address H1 = Ip4Address.valueOf("10.0.0.1");
    private static final Ip4Address H2 = Ip4Address.valueOf("10.0.0.2");
    private static final Ip4Address H3 = Ip4Address.valueOf("10.0.0.3");

    private static final String S1 = "of:0000000000000001";
    private static final String S2 = "of:0000000000000002";
    private static final String S3 = "of:0000000000000003";
    private static final String S4 = "of:0000000000000004";

    /** One hop: on this switch, traffic entering on 'in' leaves through 'out'. */
    private static final class Hop {
        final DeviceId device;
        final PortNumber in;
        final PortNumber out;

        Hop(String device, long in, long out) {
            this.device = DeviceId.deviceId(device);
            this.in = PortNumber.portNumber(in);
            this.out = PortNumber.portNumber(out);
        }
    }

    /** One direction of a tunnel: src -> dst along a fixed path. */
    private static final class Direction {
        final Ip4Address src;
        final Ip4Address dst;
        final List<Hop> hops;

        Direction(Ip4Address src, Ip4Address dst, Hop... hops) {
            this.src = src;
            this.dst = dst;
            this.hops = Arrays.asList(hops);
        }
    }

    /** Key = "<host> <tunnel>", exactly as it appears in the state file. */
    private static final Map<String, Direction> DIRECTIONS = new LinkedHashMap<>();
    static {
        // Tunnel 1 (green): H1 - S1 - S4 - S2 - H2
        DIRECTIONS.put("H1 tunnel1", new Direction(H1, H2,
                new Hop(S1, 1, 3), new Hop(S4, 1, 2), new Hop(S2, 3, 1)));
        DIRECTIONS.put("H2 tunnel1", new Direction(H2, H1,
                new Hop(S2, 1, 3), new Hop(S4, 2, 1), new Hop(S1, 3, 1)));

        // Tunnel 2 (red): H1 - S1 - S3 - H3
        DIRECTIONS.put("H1 tunnel2", new Direction(H1, H3,
                new Hop(S1, 1, 2), new Hop(S3, 2, 1)));
        DIRECTIONS.put("H3 tunnel2", new Direction(H3, H1,
                new Hop(S3, 1, 2), new Hop(S1, 2, 1)));
    }

    // ---- ONOS services ----------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;
    private ScheduledExecutorService executor;

    /** Directions currently active and the rules installed for each one. */
    private final Map<String, List<FlowRule>> installed = new ConcurrentHashMap<>();

    // ---- Lifecycle --------------------------------------------------------

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
        executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(this::poll, 0, POLL_SECONDS, TimeUnit.SECONDS);
        log.info("VPN Manager started (reading {})", STATE_FILE);
    }

    @Deactivate
    protected void deactivate() {
        if (executor != null) {
            executor.shutdownNow();
        }
        flowRuleService.removeFlowRulesById(appId);
        installed.clear();
        log.info("VPN Manager stopped");
    }

    // ---- Logic ------------------------------------------------------------

    /** Compares the file state with the installed rules and applies the differences. */
    private void poll() {
        // If an exception escapes, the executor stops calling poll() for good,
        // so everything is caught here.
        try {
            Map<String, Boolean> wanted = readStateFile();
            for (Map.Entry<String, Direction> e : DIRECTIONS.entrySet()) {
                String key = e.getKey();
                boolean accept = wanted.containsKey(key) && wanted.get(key);
                boolean active = installed.containsKey(key);
                if (accept && !active) {
                    install(key, e.getValue());
                } else if (!accept && active) {
                    remove(key);
                }
            }
        } catch (Exception ex) {
            log.warn("Error while processing {}", STATE_FILE, ex);
        }
    }

    /** Reads lines like "H1 tunnel1 accept". Missing file or entry = reject. */
    private Map<String, Boolean> readStateFile() throws IOException {
        Map<String, Boolean> state = new HashMap<>();
        List<String> lines;
        try {
            lines = Files.readAllLines(Paths.get(STATE_FILE));
        } catch (NoSuchFileException e) {
            return state;
        }
        for (String line : lines) {
            String[] p = line.trim().split("\\s+");
            if (p.length == 3) {
                state.put(p[0] + " " + p[1], p[2].equalsIgnoreCase("accept"));
            }
        }
        return state;
    }

    private void install(String key, Direction d) {
        List<FlowRule> rules = new ArrayList<>();
        for (Hop h : d.hops) {
            rules.add(buildRule(h, ipv4Selector(h, d)));
            rules.add(buildRule(h, arpSelector(h, d)));
        }
        flowRuleService.applyFlowRules(rules.toArray(new FlowRule[0]));
        installed.put(key, rules);
        log.info("{} -> ACCEPT ({} rules installed)", key, rules.size());
    }

    private void remove(String key) {
        List<FlowRule> rules = installed.remove(key);
        if (rules != null) {
            flowRuleService.removeFlowRules(rules.toArray(new FlowRule[0]));
        }
        log.info("{} -> REJECT (rules removed)", key);
    }

    // ---- Rule construction -------------------------------------------------

    private TrafficSelector ipv4Selector(Hop h, Direction d) {
        return DefaultTrafficSelector.builder()
                .matchInPort(h.in)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(d.src, 32))
                .matchIPDst(IpPrefix.valueOf(d.dst, 32))
                .build();
    }

    /** ARP follows the same path so no static ARP is needed in Mininet. */
    private TrafficSelector arpSelector(Hop h, Direction d) {
        return DefaultTrafficSelector.builder()
                .matchInPort(h.in)
                .matchEthType(Ethernet.TYPE_ARP)
                .matchArpSpa(d.src)
                .matchArpTpa(d.dst)
                .build();
    }

    private FlowRule buildRule(Hop h, TrafficSelector selector) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(h.out)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(h.device)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(PRIORITY)
                .fromApp(appId)
                .makePermanent()
                .build();
    }
}
