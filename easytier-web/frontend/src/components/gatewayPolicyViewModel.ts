import type { GatewayPolicySnapshot } from '../modules/api';

export type GatewayPolicyDevice = {
    value: string;
    label: string;
    hostname?: string;
    networkIds: string[];
};

export type GatewayPolicyRoleView = {
    role: 'source' | 'exit';
    policy: GatewayPolicySnapshot;
    peer: GatewayPolicyDevice | null;
    observedStatus: string;
    observedVersion?: number | null;
    observedIpv4?: string | null;
};

const enabledFirst = (left: GatewayPolicySnapshot, right: GatewayPolicySnapshot) => {
    if (left.desired.enabled !== right.desired.enabled) return left.desired.enabled ? -1 : 1;
    return right.desired.desired_version - left.desired.desired_version;
};

export const selectGatewayPolicyForSource = (
    policies: GatewayPolicySnapshot[],
    sourceMachineId: string,
    networkInstanceId: string,
) => (
    policies
        .filter((policy) => (
            policy.desired.source_machine_id === sourceMachineId
            && policy.desired.network_instance_id === networkInstanceId
        ))
        .sort(enabledFirst)[0] || null
);

export const selectGatewayPolicyForParticipant = (
    policies: GatewayPolicySnapshot[],
    machineId: string,
    networkInstanceId: string,
) => (
    policies
        .filter((policy) => (
            policy.desired.network_instance_id === networkInstanceId
            && (
                policy.desired.source_machine_id === machineId
                || policy.desired.exit_machine_id === machineId
            )
        ))
        .sort(enabledFirst)[0] || null
);

export const buildGatewayPolicyRoleViews = (
    policies: GatewayPolicySnapshot[],
    devices: GatewayPolicyDevice[],
    machineId: string,
    networkInstanceId: string,
): GatewayPolicyRoleView[] => {
    const networkPolicies = policies
        .filter((policy) => (
            policy.desired.network_instance_id === networkInstanceId
            && (
                policy.desired.source_machine_id === machineId
                || policy.desired.exit_machine_id === machineId
            )
        ))
        .sort(enabledFirst);

    return networkPolicies.flatMap((policy) => {
        const views: GatewayPolicyRoleView[] = [];
        if (policy.desired.source_machine_id === machineId) {
            views.push({
                role: 'source',
                policy,
                peer: devices.find((device) => device.value === policy.desired.exit_machine_id) || null,
                observedStatus: policy.observed.source?.status || 'missing',
                observedVersion: policy.observed.source?.version,
                observedIpv4: policy.observed.source?.easytier_ipv4,
            });
        }
        if (policy.desired.exit_machine_id === machineId) {
            views.push({
                role: 'exit',
                policy,
                peer: devices.find((device) => device.value === policy.desired.source_machine_id) || null,
                observedStatus: policy.observed.exit?.status || 'missing',
                observedVersion: policy.observed.exit?.version,
                observedIpv4: policy.observed.exit?.easytier_ipv4,
            });
        }
        return views;
    });
};
