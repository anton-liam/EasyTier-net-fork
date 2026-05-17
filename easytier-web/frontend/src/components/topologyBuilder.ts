import { MarkerType, Position, type Edge, type Node } from '@vue-flow/core';
import { NetworkTypes, Utils } from 'easytier-frontend-lib';
import { type GatewayPolicySnapshot } from '../modules/api';

export type TopologyDevice = {
    label: string;
    value: string;
    networkIds: string[];
    hostname?: string;
    publicIp?: string;
};

export type TopologyNodeData = {
    title: string;
    subtitle: string;
    role: string;
    status?: string;
    ipv4?: string;
};

export type TopologyEdgeData = {
    label: string;
    layer: 'control' | 'peer' | 'gateway';
};

export type GatewayTopology = {
    nodes: Node<TopologyNodeData>[];
    edges: Edge<TopologyEdgeData>[];
    controlMachineId?: string;
};

export type BuildGatewayTopologyInput = {
    devices: TopologyDevice[];
    networkInstanceId: string;
    sourceMachineId: string;
    policies: GatewayPolicySnapshot[];
    networkInfo?: NetworkTypes.NetworkInstance | null;
    controlHost?: string;
    labels?: Partial<TopologyLabels>;
};

export type TopologyLabels = {
    controlPlane: string;
    exitNode: string;
    sourceNode: string;
    currentNode: string;
    normalNode: string;
    controlLink: string;
    gatewayLink: string;
    natEgress: string;
    exitNetwork: string;
    underlayEgress: string;
};

const defaultLabels: TopologyLabels = {
    controlPlane: 'Control',
    exitNode: 'Exit',
    sourceNode: 'Source',
    currentNode: 'Current',
    normalNode: 'Node',
    controlLink: 'control / config-server',
    gatewayLink: 'gateway_full_tunnel',
    natEgress: 'NAT / egress',
    exitNetwork: 'Exit Network',
    underlayEgress: 'underlay egress',
};

const shortId = (value?: string | null) => value ? value.slice(0, 8) : '-';

const normalizeHost = (value?: string) => {
    if (!value) return '';
    try {
        return new URL(value).hostname;
    } catch {
        return value;
    }
};

const routeIpv4 = (route?: NetworkTypes.Route) => {
    if (!route?.ipv4_addr) return '';
    if (typeof route.ipv4_addr === 'string') return route.ipv4_addr;
    return Utils.ipv4InetToString(route.ipv4_addr);
};

const myIpv4 = (networkInfo?: NetworkTypes.NetworkInstance | null) => {
    const value = networkInfo?.detail?.my_node_info?.virtual_ipv4;
    return value ? Utils.ipv4InetToString(value) : '';
};

const routeCost = (info: NetworkTypes.PeerRoutePair) => {
    const cost = info.route.cost;
    if (!cost) return 'local';
    if (cost === 1) return 'p2p';
    return `relay(${cost})`;
};

const tunnelProto = (info: NetworkTypes.PeerRoutePair) => {
    const protos = new Set<string>();
    for (const conn of info.peer?.conns || []) {
        if (conn.tunnel?.tunnel_type) protos.add(conn.tunnel.tunnel_type);
    }
    return [...protos].join(',');
};

const policyForSource = (policies: GatewayPolicySnapshot[], machineId: string) => (
    policies.find((policy) => policy.desired.enabled && policy.desired.source_machine_id === machineId)
);

const observedIpv4 = (policies: GatewayPolicySnapshot[], machineId: string) => {
    for (const policy of policies) {
        if (policy.desired.source_machine_id === machineId && policy.observed.source?.easytier_ipv4) {
            return policy.observed.source.easytier_ipv4;
        }
        if (policy.desired.exit_machine_id === machineId && policy.observed.exit?.easytier_ipv4) {
            return policy.observed.exit.easytier_ipv4;
        }
    }
    return '';
};

const observedStatus = (policies: GatewayPolicySnapshot[], machineId: string) => {
    for (const policy of policies) {
        if (policy.desired.source_machine_id === machineId && policy.observed.source?.status) {
            return policy.observed.source.status;
        }
        if (policy.desired.exit_machine_id === machineId && policy.observed.exit?.status) {
            return policy.observed.exit.status;
        }
    }
    return '';
};

const inferControlMachineId = (devices: TopologyDevice[], controlHost?: string) => {
    const normalized = normalizeHost(controlHost);
    if (!normalized) return undefined;
    return devices.find((device) => normalizeHost(device.publicIp).includes(normalized))?.value;
};

const machinePosition = (
    index: number,
    total: number,
    device: TopologyDevice,
    input: BuildGatewayTopologyInput,
    controlMachineId?: string,
) => {
    if (device.value === controlMachineId) {
        return { x: 640, y: 40 };
    }

    const enabledPolicies = input.policies.filter((policy) => (
        policy.desired.enabled && policy.desired.network_instance_id === input.networkInstanceId
    ));
    const isSource = enabledPolicies.some((policy) => policy.desired.source_machine_id === device.value);
    const isExit = enabledPolicies.some((policy) => policy.desired.exit_machine_id === device.value);

    if (isSource && !isExit) {
        const sources = [...new Set(enabledPolicies.map((policy) => policy.desired.source_machine_id))];
        const sourceIndex = sources.indexOf(device.value);
        return { x: 80, y: 280 + Math.max(sourceIndex, 0) * 220 };
    }

    if (isExit) {
        const exits = [...new Set(enabledPolicies.map((policy) => policy.desired.exit_machine_id))];
        const exitIndex = exits.indexOf(device.value);
        return { x: 1080, y: 280 + Math.max(exitIndex, 0) * 220 };
    }

    const cols = Math.max(1, Math.ceil(Math.sqrt(total)));
    return {
        x: 480 + (index % cols) * 280,
        y: 600 + Math.floor(index / cols) * 180,
    };
};

const nodePosition = (
    device: TopologyDevice,
    input: BuildGatewayTopologyInput,
    controlMachineId?: string,
) => {
    const enabledPolicies = input.policies.filter((policy) => (
        policy.desired.enabled && policy.desired.network_instance_id === input.networkInstanceId
    ));
    const isSource = enabledPolicies.some((policy) => policy.desired.source_machine_id === device.value);
    const isExit = enabledPolicies.some((policy) => policy.desired.exit_machine_id === device.value);
    if (device.value === controlMachineId) {
        return { source: Position.Bottom, target: Position.Top };
    }
    if (isSource && !isExit) {
        return { source: Position.Right, target: Position.Right };
    }
    if (isExit) {
        return { source: Position.Right, target: Position.Left };
    }
    return { source: Position.Right, target: Position.Left };
};

export const buildGatewayTopology = (input: BuildGatewayTopologyInput): GatewayTopology => {
    const labels = { ...defaultLabels, ...input.labels };
    const networkDevices = input.devices.filter((device) => device.networkIds.includes(input.networkInstanceId));
    const networkPolicies = input.policies.filter((policy) => (
        policy.desired.network_instance_id === input.networkInstanceId
    ));
    const controlMachineId = inferControlMachineId(networkDevices, input.controlHost);
    const myHostname = input.networkInfo?.detail?.my_node_info?.hostname;
    const myRouteIpv4 = myIpv4(input.networkInfo);

    const nodes: Node<TopologyNodeData>[] = networkDevices.map((device, index) => {
        const policy = policyForSource(networkPolicies, device.value);
        const isCurrent = device.value === input.sourceMachineId;
        const isControl = device.value === controlMachineId;
        const isExit = networkPolicies.some((item) => item.desired.enabled && item.desired.exit_machine_id === device.value);
        const role = isControl ? labels.controlPlane : isExit ? labels.exitNode : policy ? labels.sourceNode : isCurrent ? labels.currentNode : labels.normalNode;
        const peerRoute = input.networkInfo?.detail?.peer_route_pairs.find((item) => item.route.hostname === device.hostname)?.route;
        const ipv4 = observedIpv4(networkPolicies, device.value)
            || (device.hostname === myHostname ? myRouteIpv4 : '')
            || routeIpv4(peerRoute);

        const handles = nodePosition(device, input, controlMachineId);

        return {
            id: `machine:${device.value}`,
            type: 'machine',
            position: machinePosition(index, networkDevices.length, device, input, controlMachineId),
            sourcePosition: handles.source,
            targetPosition: handles.target,
            data: {
                title: device.hostname || device.label,
                subtitle: shortId(device.value),
                role,
                status: observedStatus(networkPolicies, device.value),
                ipv4,
            },
            class: [
                'topology-machine-node',
                isControl ? 'is-control' : '',
                isExit ? 'is-exit' : '',
                policy ? 'is-source' : '',
                isCurrent ? 'is-current' : '',
            ].filter(Boolean).join(' '),
        };
    });

    const edges: Edge<TopologyEdgeData>[] = [];
    const nodeIds = new Set(nodes.map((node) => node.id));
    const currentNodeId = `machine:${input.sourceMachineId}`;

    if (controlMachineId) {
        for (const device of networkDevices) {
            if (device.value === controlMachineId) continue;
        edges.push({
            id: `control:${device.value}:${controlMachineId}`,
            source: `machine:${device.value}`,
            target: `machine:${controlMachineId}`,
            label: labels.controlLink,
            type: 'smoothstep',
            animated: true,
            zIndex: 1,
            class: 'control-edge',
            data: { layer: 'control', label: labels.controlLink },
        });
        }
    }

    for (const pair of input.networkInfo?.detail?.peer_route_pairs || []) {
        const targetDevice = networkDevices.find((device) => device.hostname === pair.route.hostname);
        if (!targetDevice || !nodeIds.has(currentNodeId)) continue;
        const targetNodeId = `machine:${targetDevice.value}`;
        if (targetNodeId === currentNodeId) continue;
        const label = [routeCost(pair), tunnelProto(pair)].filter(Boolean).join(' / ');
        edges.push({
            id: `peer:${input.sourceMachineId}:${targetDevice.value}`,
            source: currentNodeId,
            target: targetNodeId,
            label,
            type: 'default',
            zIndex: 2,
            class: 'peer-edge',
            data: { layer: 'peer', label },
        });
    }

    const exitNetworkIds = new Set<string>();
    for (const policy of networkPolicies.filter((item) => item.desired.enabled)) {
        const source = `machine:${policy.desired.source_machine_id}`;
        const exit = `machine:${policy.desired.exit_machine_id}`;
        if (!nodeIds.has(source) || !nodeIds.has(exit)) continue;
        edges.push({
            id: `gateway:${policy.desired.policy_id}:source-exit`,
            source,
            target: exit,
            label: labels.gatewayLink,
            type: 'smoothstep',
            animated: true,
            markerEnd: MarkerType.ArrowClosed,
            zIndex: 3,
            class: 'gateway-edge',
            data: { layer: 'gateway', label: labels.gatewayLink },
        });
        exitNetworkIds.add(policy.desired.exit_machine_id);
    }

    for (const exitMachineId of exitNetworkIds) {
        const exitDevice = networkDevices.find((device) => device.value === exitMachineId);
        const nodeId = `exit-network:${exitMachineId}`;
        nodes.push({
            id: nodeId,
            type: 'external',
            position: {
                x: 1480,
                y: machinePosition(0, networkDevices.length, exitDevice || networkDevices[0], input, controlMachineId).y,
            },
            targetPosition: Position.Left,
            data: {
                title: labels.exitNetwork,
                subtitle: exitDevice?.hostname || shortId(exitMachineId),
                role: labels.underlayEgress,
            },
            class: 'topology-external-node',
        });
        edges.push({
            id: `gateway:${exitMachineId}:egress`,
            source: `machine:${exitMachineId}`,
            target: nodeId,
            label: labels.natEgress,
            type: 'smoothstep',
            animated: true,
            markerEnd: MarkerType.ArrowClosed,
            zIndex: 3,
            class: 'gateway-edge',
            data: { layer: 'gateway', label: labels.natEgress },
        });
    }

    return { nodes, edges, controlMachineId };
};
