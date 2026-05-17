<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { Button, Dialog, Message, Tag } from 'primevue';
import { VueFlow } from '@vue-flow/core';
import { Background } from '@vue-flow/background';
import { Controls } from '@vue-flow/controls';
import { useI18n } from 'vue-i18n';
import '@vue-flow/core/dist/style.css';
import '@vue-flow/core/dist/theme-default.css';
import '@vue-flow/controls/dist/style.css';
import ApiClient, { type GatewayPolicyObservedNode, type GatewayPolicySnapshot } from '../modules/api';
import { NetworkTypes } from 'easytier-frontend-lib';
import { buildGatewayTopology, type TopologyDevice } from './topologyBuilder';

type DeviceOption = TopologyDevice;
type CheckSeverity = 'success' | 'warn' | 'danger';
type CheckItem = { label: string; detail: string; severity: CheckSeverity };

const props = defineProps<{
    api?: ApiClient;
    visible: boolean;
    devices: DeviceOption[];
    sourceMachineId: string;
    networkInstanceId: string;
    networkInfo?: NetworkTypes.NetworkInstance | null;
    controlHost?: string;
    policy?: GatewayPolicySnapshot | null;
}>();

const emit = defineEmits<{
    'update:visible': [value: boolean];
}>();

const { t } = useI18n();
const loading = ref(false);
const loadError = ref('');
const currentPolicy = ref<GatewayPolicySnapshot | null>(null);
const gatewayPolicies = ref<GatewayPolicySnapshot[]>([]);
const checkItems = ref<CheckItem[]>([]);
const checkedAt = ref('');

const shortId = (value?: string | null) => value ? value.slice(0, 8) : '-';

const sourceDevice = computed(() => props.devices.find((device) => device.value === props.sourceMachineId));
const policy = computed(() => currentPolicy.value || props.policy || null);
const desired = computed(() => policy.value?.desired || null);
const observed = computed(() => policy.value?.observed || null);
const exitDevice = computed(() => props.devices.find((device) => device.value === desired.value?.exit_machine_id));

const nodeLabel = (machineId?: string | null) => (
    props.devices.find((device) => device.value === machineId)?.label || `EasyTier (${shortId(machineId)})`
);

const topologyLabels = computed(() => ({
    controlPlane: t('web.gateway_policy.control_plane'),
    exitNode: t('web.gateway_policy.exit_node'),
    sourceNode: t('web.gateway_policy.source_node'),
    currentNode: t('web.gateway_policy.current_node'),
    normalNode: t('web.gateway_policy.normal_node'),
    controlLink: t('web.gateway_policy.control_link'),
    gatewayLink: t('web.gateway_policy.gateway_link'),
    natEgress: t('web.gateway_policy.nat_egress'),
    exitNetwork: t('web.gateway_policy.exit_network'),
    underlayEgress: t('web.gateway_policy.underlay_egress'),
}));

const selectCurrentSourcePolicy = (policies: GatewayPolicySnapshot[]) => (
    policies
        .filter((item) => (
            item.desired.source_machine_id === props.sourceMachineId
            && item.desired.network_instance_id === props.networkInstanceId
        ))
        .sort((left, right) => {
            if (left.desired.enabled !== right.desired.enabled) return left.desired.enabled ? -1 : 1;
            return right.desired.desired_version - left.desired.desired_version;
        })[0] || null
);

const observedStatusSeverity = (node?: GatewayPolicyObservedNode | null) => {
    if (!node) return 'secondary';
    if (node.status === 'active' || node.status === 'prepared') return 'success';
    if (node.status === 'degraded' || node.status === 'rollbacked') return 'warn';
    return 'danger';
};

const observedAligned = computed(() => {
    const snapshot = policy.value;
    if (!snapshot?.desired.enabled || !snapshot.observed.source || !snapshot.observed.exit) return false;
    const desiredVersion = Number(snapshot.desired.desired_version);
    return snapshot.observed.source.policy_id === snapshot.desired.policy_id
        && snapshot.observed.exit.policy_id === snapshot.desired.policy_id
        && Number(snapshot.observed.source.version) === desiredVersion
        && Number(snapshot.observed.exit.version) === desiredVersion;
});

const policyStatusSeverity = computed(() => {
    if (!desired.value?.enabled) return 'secondary';
    if (!observed.value?.source || !observed.value?.exit) return 'warn';
    if (
        observed.value.source.status === 'active'
        && ['prepared', 'active'].includes(observed.value.exit.status)
        && observedAligned.value
    ) {
        return 'success';
    }
    return 'warn';
});

const policyStatusText = computed(() => {
    if (!desired.value) return t('web.gateway_policy.status_not_configured');
    if (!desired.value.enabled) return t('web.gateway_policy.status_disabled');
    if (!observed.value?.source || !observed.value?.exit) return t('web.gateway_policy.status_waiting_report');
    if (!observedAligned.value) {
        return t('web.gateway_policy.status_version_mismatch');
    }
    if (policyStatusSeverity.value === 'success') return t('web.gateway_policy.status_applied');
    return t('web.gateway_policy.status_needs_check');
});

const flowSubtitle = computed(() => {
    if (!desired.value) return t('web.gateway_policy.no_policy_for_instance');
    const cidrs = desired.value.managed_cidrs.length ? desired.value.managed_cidrs.join(', ') : t('web.gateway_policy.device_traffic');
    return `${desired.value.enabled ? '' : `${t('web.gateway_policy.status_disabled')}: `}${cidrs} -> ${nodeLabel(desired.value.exit_machine_id)}`;
});

const topology = computed(() => buildGatewayTopology({
    devices: props.devices,
    networkInstanceId: props.networkInstanceId,
    sourceMachineId: props.sourceMachineId,
    policies: gatewayPolicies.value.length ? gatewayPolicies.value : (props.policy ? [props.policy] : []),
    networkInfo: props.networkInfo,
    controlHost: props.controlHost,
    labels: topologyLabels.value,
}));

const legendItems = computed(() => [
    { label: t('web.gateway_policy.legend_control'), className: 'legend-control' },
    { label: t('web.gateway_policy.legend_peer'), className: 'legend-peer' },
    { label: t('web.gateway_policy.legend_gateway'), className: 'legend-gateway' },
]);

const refreshPolicy = async () => {
    if (!props.api || !props.sourceMachineId || !props.networkInstanceId) return;
    loading.value = true;
    loadError.value = '';
    try {
        const policies = await props.api.list_gateway_policies();
        gatewayPolicies.value = policies.filter((item) => (
            item.desired.network_instance_id === props.networkInstanceId
        ));
        currentPolicy.value = selectCurrentSourcePolicy(policies);
    } catch (e) {
        loadError.value = String(e);
    } finally {
        loading.value = false;
    }
};

watch(() => [props.visible, props.sourceMachineId, props.networkInstanceId], () => {
    if (!props.visible) return;
    currentPolicy.value = props.policy || null;
    gatewayPolicies.value = props.policy ? [props.policy] : [];
    checkItems.value = [];
    checkedAt.value = '';
    refreshPolicy();
}, { immediate: true });

const addCheck = (items: CheckItem[], ok: boolean, label: string, success: string, fail: string, warn = false) => {
    items.push({
        label,
        detail: ok ? success : fail,
        severity: ok ? 'success' : (warn ? 'warn' : 'danger'),
    });
};

const runExitCheck = async () => {
    await refreshPolicy();
    const snapshot = currentPolicy.value || props.policy || null;
    const items: CheckItem[] = [];
    if (!snapshot) {
        checkItems.value = [{
            label: t('web.gateway_policy.title'),
            detail: t('web.gateway_policy.no_policy_for_instance'),
            severity: 'warn',
        }];
        checkedAt.value = new Date().toLocaleTimeString();
        return;
    }

    const sourceOnline = !!sourceDevice.value?.networkIds.includes(snapshot.desired.network_instance_id);
    const exitOnline = !!exitDevice.value?.networkIds.includes(snapshot.desired.network_instance_id);
    const source = snapshot.observed.source;
    const exit = snapshot.observed.exit;
    const version = snapshot.desired.desired_version;
    const trafficScoped = snapshot.desired.managed_cidrs.length > 0 || snapshot.desired.include_device_traffic;

    addCheck(items, snapshot.desired.enabled, t('web.gateway_policy.check_policy_enabled'), `desired version ${version} ${t('web.gateway_policy.enabled')}`, t('web.gateway_policy.policy_disabled'), true);
    addCheck(items, sourceOnline, t('web.gateway_policy.check_source_online'), `${nodeLabel(snapshot.desired.source_machine_id)} ${t('web.gateway_policy.running_current_network')}`, t('web.gateway_policy.source_not_in_network'));
    addCheck(items, exitOnline, t('web.gateway_policy.check_exit_online'), `${nodeLabel(snapshot.desired.exit_machine_id)} ${t('web.gateway_policy.running_current_network')}`, t('web.gateway_policy.exit_not_in_network'));
    addCheck(items, !!source?.easytier_ipv4, t('web.gateway_policy.check_source_ipv4'), source?.easytier_ipv4 || '', t('web.gateway_policy.source_ipv4_missing'));
    addCheck(items, !!exit?.easytier_ipv4, t('web.gateway_policy.check_exit_ipv4'), exit?.easytier_ipv4 || '', t('web.gateway_policy.exit_ipv4_missing'));
    addCheck(items, source?.status === 'active', t('web.gateway_policy.check_source_status'), source?.status || 'missing', `${t('web.gateway_policy.source_status_is')} ${source?.status || 'missing'}`);
    addCheck(items, !!exit && ['prepared', 'active'].includes(exit.status), t('web.gateway_policy.check_exit_status'), exit?.status || 'missing', `${t('web.gateway_policy.exit_status_is')} ${exit?.status || 'missing'}`);
    addCheck(items, source?.version === version, t('web.gateway_policy.check_source_version'), `observed=${source?.version}`, `desired=${version}, observed=${source?.version ?? 'missing'}`);
    addCheck(items, exit?.version === version, t('web.gateway_policy.check_exit_version'), `observed=${exit?.version}`, `desired=${version}, observed=${exit?.version ?? 'missing'}`);
    addCheck(items, trafficScoped, t('web.gateway_policy.check_managed_scope'), t('web.gateway_policy.managed_scope_ok'), t('web.gateway_policy.managed_scope_empty'));

    checkItems.value = items;
    checkedAt.value = new Date().toLocaleTimeString();
};
</script>

<template>
    <Dialog :visible="visible" @update:visible="emit('update:visible', $event)" modal class="w-full md:w-11/12 lg:w-10/12" :header="t('web.gateway_policy.topology_title')">
        <div class="space-y-4">
            <Message v-if="loadError" severity="error" :closable="false">{{ loadError }}</Message>

            <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                    <div class="text-base font-medium">{{ flowSubtitle }}</div>
                    <div class="text-sm text-secondary font-mono">network {{ shortId(networkInstanceId) }}</div>
                </div>
                <div class="flex items-center gap-2">
                    <div class="hidden flex-wrap items-center gap-3 md:flex">
                        <div v-for="item in legendItems" :key="item.label" class="legend-item">
                            <span :class="['legend-line', item.className]"></span>
                            <span>{{ item.label }}</span>
                        </div>
                    </div>
                    <Tag :severity="policyStatusSeverity" :value="policyStatusText" />
                    <Button icon="pi pi-refresh" severity="secondary" :loading="loading" @click="refreshPolicy" />
                </div>
            </div>

            <Message v-if="!desired" severity="warn" :closable="false">
                {{ t('web.gateway_policy.no_policy_for_instance') }}
            </Message>

            <div class="topology-layout">
                <div class="topology-canvas">
                    <VueFlow
                        :nodes="topology.nodes"
                        :edges="topology.edges"
                        fit-view-on-init
                        :fit-view-options="{ padding: 0.22, minZoom: 0.35, maxZoom: 1.15 }"
                        :default-viewport="{ x: 0, y: 0, zoom: 0.8 }"
                        :min-zoom="0.25"
                        :max-zoom="1.4"
                        :nodes-draggable="false"
                        :nodes-connectable="false"
                        :edges-updatable="false"
                        :zoom-on-double-click="false"
                        class="gateway-flow"
                    >
                        <Background pattern-color="#d1d5db" :gap="32" />
                        <Controls position="bottom-right" />

                        <template #node-machine="{ data }">
                            <div class="flow-node">
                                <div class="node-kicker">{{ data.role }}</div>
                                <div class="node-title">{{ data.title }}</div>
                                <div class="node-meta font-mono">{{ data.subtitle }}</div>
                                <div class="mt-2 flex flex-wrap gap-1">
                                    <Tag v-if="data.ipv4" severity="info" :value="data.ipv4" />
                                    <Tag v-if="data.status" :severity="observedStatusSeverity({ status: data.status, machine_id: '', agent_version: '' })" :value="data.status" />
                                </div>
                            </div>
                        </template>

                        <template #node-external="{ data }">
                            <div class="flow-node external">
                                <div class="node-kicker">{{ data.role }}</div>
                                <div class="node-title">{{ data.title }}</div>
                                <div class="node-meta">{{ data.subtitle }}</div>
                            </div>
                        </template>
                    </VueFlow>
                </div>
                <div v-if="desired" class="topology-action-panel">
                    <div class="panel-section">
                        <div class="font-medium">{{ t('web.gateway_policy.current_source_policy') }}</div>
                        <div class="mt-2 text-sm text-secondary">
                            {{ nodeLabel(desired.source_machine_id) }} -> {{ nodeLabel(desired.exit_machine_id) }}
                        </div>
                        <div class="mt-3 space-y-1 text-sm">
                            <div><span class="text-secondary">CIDR</span> {{ desired.managed_cidrs.join(', ') || '-' }}</div>
                            <div><span class="text-secondary">{{ t('web.gateway_policy.ingress_iface') }}</span> {{ desired.ingress_ifaces.join(', ') || 'auto' }}</div>
                            <div><span class="text-secondary">{{ t('web.gateway_policy.device_traffic_label') }}</span> {{ desired.include_device_traffic ? t('web.common.enable') : t('web.common.disable') }}</div>
                            <div><span class="text-secondary">{{ t('web.gateway_policy.exit_egress') }}</span> {{ desired.exit_egress.mode === 'interface' ? desired.exit_egress.iface || 'interface' : 'auto' }}</div>
                        </div>
                    </div>
                    <Button class="mt-4 w-full" icon="pi pi-bolt" :label="t('web.gateway_policy.test_exit')" :loading="loading" @click="runExitCheck" />
                </div>
            </div>

            <div v-if="desired" class="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div class="rounded-md border border-surface-200 p-3">
                    <div class="mb-2 font-medium">{{ t('web.gateway_policy.desired') }}</div>
                    <div class="kv-row"><span>policy</span><span class="font-mono">{{ shortId(desired.policy_id) }}</span></div>
                    <div class="kv-row"><span>version</span><span>{{ desired.desired_version }}</span></div>
                    <div class="kv-row"><span>enabled</span><span>{{ desired.enabled ? 'true' : 'false' }}</span></div>
                </div>
                <div class="rounded-md border border-surface-200 p-3">
                    <div class="mb-2 font-medium">{{ t('web.gateway_policy.observed') }}</div>
                    <div class="kv-row"><span>source version</span><span>{{ observed?.source?.version ?? '-' }}</span></div>
                    <div class="kv-row"><span>exit version</span><span>{{ observed?.exit?.version ?? '-' }}</span></div>
                    <div class="kv-row"><span>last error</span><span class="truncate">{{ observed?.source?.last_error || observed?.exit?.last_error || '-' }}</span></div>
                </div>
            </div>

            <div v-if="checkItems.length" class="rounded-md border border-surface-200 p-3">
                <div class="mb-3 flex items-center justify-between">
                    <div class="font-medium">{{ t('web.gateway_policy.exit_test_result') }}</div>
                    <div class="text-sm text-secondary">{{ checkedAt }}</div>
                </div>
                <div class="space-y-2">
                    <div v-for="item in checkItems" :key="item.label" class="check-row">
                        <Tag :severity="item.severity" :value="item.severity === 'success' ? 'PASS' : item.severity === 'warn' ? 'WARN' : 'FAIL'" />
                        <div>
                            <div class="font-medium">{{ item.label }}</div>
                            <div class="text-sm text-secondary">{{ item.detail }}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </Dialog>
</template>

<style scoped>
.topology-canvas {
    height: 44rem;
    min-height: 36rem;
    overflow: hidden;
    border: 1px solid var(--surface-200, #e5e7eb);
    border-radius: 0.375rem;
    background: var(--surface-ground, #f8fafc);
    min-width: 0;
}

.topology-layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 18rem;
    gap: 1rem;
}

.gateway-flow {
    height: 100%;
}

.flow-node {
    min-width: 12.5rem;
    max-width: 15rem;
    border: 1px solid var(--surface-200, #e5e7eb);
    border-radius: 0.375rem;
    padding: 0.75rem;
    background: var(--surface-card, #ffffff);
    box-shadow: 0 0.25rem 0.75rem rgba(15, 23, 42, 0.07);
}

.flow-node.external {
    border-style: dashed;
}

.node-kicker {
    font-size: 0.75rem;
    color: var(--text-color-secondary, #64748b);
}

.node-title {
    margin-top: 0.25rem;
    font-weight: 600;
    line-height: 1.25;
    overflow-wrap: anywhere;
}

.node-meta {
    margin-top: 0.25rem;
    font-size: 0.85rem;
    color: var(--text-color-secondary, #64748b);
    overflow-wrap: anywhere;
}

.topology-action-panel {
    align-self: start;
    border: 1px solid var(--surface-200, #e5e7eb);
    border-radius: 0.375rem;
    padding: 0.875rem;
    background: var(--surface-card, #ffffff);
}

.legend-item {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    font-size: 0.82rem;
    color: var(--text-color-secondary, #64748b);
}

.legend-line {
    display: inline-block;
    width: 1.75rem;
    height: 0;
    border-top: 2px solid currentColor;
}

.legend-control {
    color: #2563eb;
    border-top-style: dashed;
}

.legend-peer {
    color: #64748b;
}

.legend-gateway {
    color: #16a34a;
    border-top-width: 3px;
}

.kv-row {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.25rem 0;
    color: var(--text-color-secondary, #64748b);
}

.kv-row span:last-child {
    color: var(--text-color, #111827);
    text-align: right;
    overflow-wrap: anywhere;
}

.check-row {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 0.75rem;
    align-items: start;
}

@media (max-width: 768px) {
    .topology-layout {
        grid-template-columns: 1fr;
    }

    .topology-canvas {
        height: 40rem;
    }
}

:deep(.vue-flow__node-machine),
:deep(.vue-flow__node-external) {
    border: none;
    background: transparent;
    padding: 0;
}

:deep(.topology-machine-node.is-current .flow-node) {
    border-color: var(--primary-color, #2563eb);
}

:deep(.topology-machine-node.is-control .flow-node) {
    border-color: #2563eb;
}

:deep(.topology-machine-node.is-source .flow-node) {
    border-color: #06b6d4;
}

:deep(.topology-machine-node.is-exit .flow-node) {
    border-color: #16a34a;
}

:deep(.control-edge .vue-flow__edge-path) {
    stroke: #2563eb;
    stroke-width: 2.4;
    stroke-dasharray: 10 7;
}

:deep(.peer-edge .vue-flow__edge-path) {
    stroke: #64748b;
    stroke-width: 2;
}

:deep(.gateway-edge .vue-flow__edge-path) {
    stroke: #16a34a;
    stroke-width: 3.6;
}

:deep(.gateway-edge .vue-flow__edge-textbg) {
    fill: var(--surface-card, #ffffff);
}

:deep(.vue-flow__edge-text) {
    font-size: 0.75rem;
    fill: var(--text-color, #111827);
}
</style>
