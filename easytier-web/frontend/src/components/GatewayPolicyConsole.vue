<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Button, Card, Column, DataTable, Drawer, ProgressSpinner, Tag, useToast } from 'primevue';
import { Utils } from 'easytier-frontend-lib';
import { useI18n } from 'vue-i18n';
import ApiClient, { type GatewayFullTunnelPolicy, type GatewayPolicyNode, type GatewayPolicySnapshot } from '../modules/api';
import GatewayPolicyEditor from './GatewayPolicyEditor.vue';

type DeviceOption = { label: string; value: string; networkIds: string[] };

const props = defineProps<{ api?: ApiClient }>();
const toast = useToast();
const { t } = useI18n();

const policies = ref<GatewayPolicySnapshot[] | undefined>(undefined);
const devices = ref<DeviceOption[]>([]);
const gatewayNodes = ref<GatewayPolicyNode[]>([]);
const selectedPolicy = ref<GatewayPolicySnapshot | null>(null);
const detailVisible = ref(false);
const editorVisible = ref(false);
const editingPolicy = ref<GatewayPolicySnapshot | null>(null);
const initialSourceMachineId = ref('');
const initialExitMachineId = ref('');
const loading = computed(() => policies.value === undefined);

const statusSeverity = (status?: string | null) => {
    if (!status) return 'secondary';
    if (status === 'active' || status === 'prepared') return 'success';
    if (status === 'degraded' || status === 'rollbacked') return 'warn';
    if (status === 'rollbacking') return 'danger';
    return 'info';
};

const boolLabel = (value: boolean) => value ? t('web.common.enable') : t('web.common.disable');
const shortId = (value?: string | null) => value ? value.slice(0, 8) : '-';
const lastError = (policy: GatewayPolicySnapshot) => policy.observed.source?.last_error || policy.observed.exit?.last_error || '';
const versionAligned = (policy: GatewayPolicySnapshot) => {
    const desired = policy.desired.desired_version;
    return policy.observed.source?.version === desired && policy.observed.exit?.version === desired;
};
const staleAfterMs = 120_000;
const AGENT_REPORTED_NETWORK_ID = '00000000-0000-0000-0000-000000000000';

const deviceOptions = computed(() => devices.value);

const loadPolicies = async () => {
    if (!props.api) return;
    policies.value = await props.api.list_gateway_policies();
};

const loadDevices = async () => {
    if (!props.api) return;
    const machineOptions = (await props.api.list_machines())
        .map((machine) => Utils.buildDeviceInfo(machine))
        .filter((device) => !!device.machine_id)
        .map((device) => ({
            label: `${device.hostname || 'WebClient'} (${shortId(device.machine_id)})`,
            value: device.machine_id,
            networkIds: device.running_network_instances || [],
        }));

    const nodes = await props.api.list_gateway_nodes();
    gatewayNodes.value = nodes;
    const nodeOptions = nodes
        .filter((node: GatewayPolicyNode) => !!node.machine_id)
        .map((node: GatewayPolicyNode) => ({
            label: `Agent ${node.easytier_ipv4 || 'unknown'} (${shortId(node.machine_id)})`,
            value: node.machine_id,
            networkIds: [AGENT_REPORTED_NETWORK_ID],
        }));

    const merged = new Map<string, DeviceOption>();
    for (const option of machineOptions) merged.set(option.value, option);
    for (const option of nodeOptions) merged.set(option.value, option);
    devices.value = Array.from(merged.values());
};

const isNodeFresh = (node?: GatewayPolicyNode | null) => {
    if (!node) return false;
    if (!node.last_report_at) return false;
    const ts = Date.parse(node.last_report_at);
    if (Number.isNaN(ts)) return false;
    return Date.now() - ts <= staleAfterMs;
};

const policyValid = (policy: GatewayPolicySnapshot) => {
    const source = gatewayNodes.value.find((node) => node.machine_id === policy.desired.source_machine_id);
    const exit = gatewayNodes.value.find((node) => node.machine_id === policy.desired.exit_machine_id);
    return !!source && !!exit && isNodeFresh(source) && isNodeFresh(exit) && source.status !== 'rollbacking' && exit.status !== 'rollbacking';
};

const policyValidityLabel = (policy: GatewayPolicySnapshot) => policyValid(policy) ? t('web.gateway_policy.valid') : t('web.gateway_policy.invalid');

const openCreate = () => {
    editingPolicy.value = null;
    initialSourceMachineId.value = '';
    initialExitMachineId.value = '';
    editorVisible.value = true;
};

const openEdit = (policy: GatewayPolicySnapshot) => {
    editingPolicy.value = policy;
    initialSourceMachineId.value = '';
    initialExitMachineId.value = '';
    editorVisible.value = true;
};

const reloadAll = async () => {
    await Promise.all([loadPolicies(), loadDevices()]);
};

const clonePolicyWith = (policy: GatewayPolicySnapshot, patch: Partial<GatewayFullTunnelPolicy>): GatewayFullTunnelPolicy => ({
    ...policy.desired,
    ...patch,
    desired_version: policy.desired.desired_version + 1,
});

const setPolicyEnabled = async (policy: GatewayPolicySnapshot, enabled: boolean) => {
    if (!props.api) return;
    if (enabled && !window.confirm(t('web.gateway_policy.confirm_enable_policy'))) return;
    await props.api.upsert_gateway_policy(clonePolicyWith(policy, { enabled }));
    await reloadAll();
};

const confirmEdit = (policy: GatewayPolicySnapshot) => {
    if (policy.desired.enabled && !window.confirm(t('web.gateway_policy.confirm_edit_enabled_policy'))) return;
    openEdit(policy);
};

const openDetails = (policy: GatewayPolicySnapshot) => {
    selectedPolicy.value = policy;
    detailVisible.value = true;
};

const periodFunc = new Utils.PeriodicTask(async () => {
    try {
        await reloadAll();
    } catch (e) {
        toast.add({ severity: 'error', summary: t('web.gateway_policy.load_failed'), detail: String(e), life: 2000 });
        console.error(e);
    }
}, 1500);

onMounted(() => periodFunc.start());
onUnmounted(() => periodFunc.stop());
</script>

<template>
    <div class="space-y-4">
        <div class="flex items-center justify-between gap-3">
            <div>
                <h1 class="text-xl font-semibold text-gray-900 dark:text-gray-100">{{ t('web.gateway_policy.title') }}</h1>
                <p class="text-sm text-gray-500 dark:text-gray-400">{{ t('web.gateway_policy.console_description') }}</p>
            </div>
            <div class="flex items-center gap-2">
                <Button icon="pi pi-refresh" severity="secondary" rounded @click="reloadAll" />
                <Button icon="pi pi-plus" :label="t('web.gateway_policy.create_policy')" @click="openCreate" />
            </div>
        </div>

        <Card>
            <template #content>
                <div v-if="loading" class="w-full flex justify-center py-8">
                    <ProgressSpinner />
                </div>
                <div v-else-if="policies?.length === 0" class="py-10 text-center text-gray-500">
                    <div class="text-base font-medium">{{ t('web.gateway_policy.empty_title') }}</div>
                    <div class="text-sm mt-1">{{ t('web.gateway_policy.empty_description') }}</div>
                </div>
                <DataTable v-else :value="policies" dataKey="desired.policy_id" stripedRows responsiveLayout="scroll">
                    <Column :header="t('web.gateway_policy.enabled_column')">
                        <template #body="slotProps">
                            <Tag :severity="slotProps.data.desired.enabled ? 'success' : 'secondary'" :value="slotProps.data.desired.enabled ? t('web.common.enable') : t('web.common.disable')" />
                        </template>
                    </Column>
                    <Column :header="t('web.gateway_policy.policy_status')">
                        <template #body="slotProps">
                            <Tag :severity="policyValid(slotProps.data) ? 'success' : 'danger'" :value="policyValidityLabel(slotProps.data)" />
                        </template>
                    </Column>
                    <Column header="Source">
                        <template #body="slotProps">{{ shortId(slotProps.data.desired.source_machine_id) }}</template>
                    </Column>
                    <Column header="Exit">
                        <template #body="slotProps">{{ shortId(slotProps.data.desired.exit_machine_id) }}</template>
                    </Column>
                    <Column :header="t('web.gateway_policy.managed_cidrs_column')">
                        <template #body="slotProps">{{ slotProps.data.desired.managed_cidrs.join(', ') || '-' }}</template>
                    </Column>
                    <Column :header="t('web.gateway_policy.device_traffic_label')">
                        <template #body="slotProps">{{ boolLabel(slotProps.data.desired.include_device_traffic) }}</template>
                    </Column>
                    <Column :header="t('web.gateway_policy.source_status')">
                        <template #body="slotProps">
                            <Tag :severity="statusSeverity(slotProps.data.observed.source?.status)" :value="slotProps.data.observed.source?.status || 'unknown'" />
                        </template>
                    </Column>
                    <Column :header="t('web.gateway_policy.exit_status')">
                        <template #body="slotProps">
                            <Tag :severity="statusSeverity(slotProps.data.observed.exit?.status)" :value="slotProps.data.observed.exit?.status || 'unknown'" />
                        </template>
                    </Column>
                    <Column :header="t('web.gateway_policy.version')">
                        <template #body="slotProps">
                            <Tag :severity="versionAligned(slotProps.data) ? 'success' : 'warn'" :value="slotProps.data.desired.desired_version" />
                        </template>
                    </Column>
                    <Column :header="t('web.gateway_policy.last_error')">
                        <template #body="slotProps">
                            <span class="text-sm text-red-600 break-all">{{ lastError(slotProps.data) || '-' }}</span>
                        </template>
                    </Column>
                    <Column :header="t('web.gateway_policy.actions')">
                        <template #body="slotProps">
                            <div class="flex items-center gap-2">
                                <Button icon="pi pi-eye" severity="secondary" rounded @click="openDetails(slotProps.data)" />
                                <Button icon="pi pi-pencil" severity="secondary" rounded @click="confirmEdit(slotProps.data)" />
                                <Button
                                    :icon="slotProps.data.desired.enabled ? 'pi pi-pause' : 'pi pi-play'"
                                    :severity="slotProps.data.desired.enabled ? 'warn' : 'success'"
                                    rounded
                                    @click="setPolicyEnabled(slotProps.data, !slotProps.data.desired.enabled)"
                                />
                            </div>
                        </template>
                    </Column>
                </DataTable>
            </template>
        </Card>

        <Drawer v-model:visible="detailVisible" position="right" class="w-full md:w-2/5" :header="t('web.gateway_policy.policy_detail')">
            <div v-if="selectedPolicy" class="space-y-4 text-sm">
                <section>
                    <h2 class="font-semibold mb-2">Desired</h2>
                    <dl class="grid grid-cols-1 gap-2">
                        <div><dt class="text-gray-500">Policy ID</dt><dd class="font-mono break-all">{{ selectedPolicy.desired.policy_id }}</dd></div>
                        <div><dt class="text-gray-500">Source</dt><dd class="font-mono break-all">{{ selectedPolicy.desired.source_machine_id }}</dd></div>
                        <div><dt class="text-gray-500">Exit</dt><dd class="font-mono break-all">{{ selectedPolicy.desired.exit_machine_id }}</dd></div>
                        <div><dt class="text-gray-500">Network Instance</dt><dd class="font-mono break-all">{{ selectedPolicy.desired.network_instance_id }}</dd></div>
                        <div><dt class="text-gray-500">Ingress Ifaces</dt><dd>{{ selectedPolicy.desired.ingress_ifaces.join(', ') || 'auto' }}</dd></div>
                        <div><dt class="text-gray-500">Exit Egress</dt><dd>{{ selectedPolicy.desired.exit_egress.mode }} {{ selectedPolicy.desired.exit_egress.iface || '' }}</dd></div>
                    </dl>
                </section>
                <section>
                    <h2 class="font-semibold mb-2">Observed Source</h2>
                    <pre class="text-xs overflow-auto bg-gray-50 dark:bg-gray-900 p-3 rounded">{{ JSON.stringify(selectedPolicy.observed.source, null, 2) }}</pre>
                </section>
                <section>
                    <h2 class="font-semibold mb-2">Observed Exit</h2>
                    <pre class="text-xs overflow-auto bg-gray-50 dark:bg-gray-900 p-3 rounded">{{ JSON.stringify(selectedPolicy.observed.exit, null, 2) }}</pre>
                </section>
            </div>
        </Drawer>

        <GatewayPolicyEditor
            v-model:visible="editorVisible"
            :api="api"
            :devices="deviceOptions"
            :policy="editingPolicy"
            :initial-source-machine-id="initialSourceMachineId"
            :initial-exit-machine-id="initialExitMachineId"
            @saved="reloadAll"
        />
    </div>
</template>
