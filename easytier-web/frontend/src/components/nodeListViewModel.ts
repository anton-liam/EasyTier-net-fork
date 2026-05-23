import type { GatewayNodeView } from '../modules/api';

export type NodeDisabledReason =
    | 'offline'
    | 'agent_offline'
    | 'missing_easytier_ipv4'
    | 'missing_lan_cidrs'
    | 'same_as_source'
    | 'no_shared_network'
    | null;

export const nodeLabel = (node: GatewayNodeView): string => {
    const name = node.hostname || node.machine_id;
    const ip = node.public_ip ? ` / ${node.public_ip}` : '';
    return `${name}${ip}`;
};

export const statusSeverity = (status?: string | null): 'success' | 'secondary' | 'warn' | 'danger' | 'info' => {
    switch ((status || '').toLowerCase()) {
        case 'active':
        case 'prepared':
        case 'online':
            return 'success';
        case 'planned':
            return 'info';
        case 'degraded':
        case 'rollbacked':
            return 'danger';
        case 'disabled':
            return 'secondary';
        default:
            return 'warn';
    }
};

export const sharedNetworkInstances = (source?: GatewayNodeView | null, exit?: GatewayNodeView | null): string[] => {
    if (!source || !exit) return [];
    const exitNetworks = new Set(exit.running_network_instances);
    return source.running_network_instances.filter((networkId) => exitNetworks.has(networkId));
};

export const sourceDisabledReason = (node?: GatewayNodeView | null): NodeDisabledReason => {
    if (!node?.machine_online) return 'offline';
    if (!node.agent.online) return 'agent_offline';
    if (node.agent.lan_cidrs.length === 0) return 'missing_lan_cidrs';
    return null;
};

export const exitDisabledReason = (
    node?: GatewayNodeView | null,
    source?: GatewayNodeView | null,
): NodeDisabledReason => {
    if (!node?.machine_online) return 'offline';
    if (!node.agent.online) return 'agent_offline';
    if (source && node.machine_id === source.machine_id) return 'same_as_source';
    return null;
};
