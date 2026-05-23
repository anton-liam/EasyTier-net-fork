<script setup lang="ts">
import { Button, Column, DataTable, ProgressSpinner, Tag, useToast } from 'primevue';
import { Utils } from 'easytier-frontend-lib';
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import ApiClient, { type GatewayNodeView, type GatewayPolicySnapshot } from '../modules/api';
import NodeGatewayDialog from './NodeGatewayDialog.vue';
import { nodeLabel, sourceDisabledReason, statusSeverity } from './nodeListViewModel';

const props = defineProps<{
    api?: ApiClient,
}>();

const { t } = useI18n();
const toast = useToast();

const nodes = ref<GatewayNodeView[]>([]);
const policies = ref<GatewayPolicySnapshot[]>([]);
const loading = ref(false);
const dialogVisible = ref(false);
const selectedSourceId = ref<string | null>(null);

const readyNodeCount = computed(() => nodes.value.filter((node) => (
    node.machine_online && node.agent.online
)).length);

const activePolicies = computed(() => policies.value.filter((policy) => policy.desired.enabled));

const loadAll = async () => {
    if (!props.api) return;
    loading.value = true;
    try {
        const [nodeResp, policyResp] = await Promise.all([
            props.api.list_gateway_node_views(),
            props.api.list_gateway_policies(),
        ]);
        nodes.value = nodeResp;
        policies.value = policyResp;
    } catch (e) {
        toast.add({ severity: 'error', summary: t('web.node_list.load_failed'), detail: String(e), life: 3000 });
    } finally {
        loading.value = false;
    }
};

const periodFunc = new Utils.PeriodicTask(async () => {
    await loadAll();
}, 3000);

onMounted(async () => {
    await loadAll();
    periodFunc.start();
});

onUnmounted(() => {
    periodFunc.stop();
});

const activePolicyForSource = (machineId: string): GatewayPolicySnapshot | undefined => (
    activePolicies.value.find((policy) => policy.desired.source_machine_id === machineId)
);

const openGatewayDialog = (node?: GatewayNodeView) => {
    selectedSourceId.value = node?.machine_id || null;
    dialogVisible.value = true;
};

const disablePolicy = async (policy: GatewayPolicySnapshot) => {
    if (!props.api) return;
    try {
        await props.api.disable_gateway_policy(policy.desired.policy_id);
        toast.add({ severity: 'success', summary: t('web.node_list.disable_success'), life: 2000 });
        await loadAll();
    } catch (e) {
        toast.add({ severity: 'error', summary: t('web.node_list.disable_failed'), detail: String(e), life: 3000 });
    }
};

const shortId = (value: string) => value.slice(0, 8);

const sourceDisabledReasonLabel = (node: GatewayNodeView): string | null => {
    const reason = sourceDisabledReason(node);
    return reason ? t(`web.node_list.reason_${reason}`) : null;
};
</script>

<template>
    <div class="flex flex-col gap-4">
        <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
                <h1 class="text-xl font-semibold text-gray-900 dark:text-gray-100">{{ t('web.node_list.title') }}</h1>
                <div class="mt-1 flex flex-wrap gap-2">
                    <Tag severity="info" :value="`${nodes.length} ${t('web.node_list.nodes')}`" />
                    <Tag severity="success" :value="`${readyNodeCount} ${t('web.node_list.ready_nodes')}`" />
                    <Tag severity="secondary" :value="`${activePolicies.length} ${t('web.node_list.active_policies')}`" />
                </div>
            </div>
            <div class="flex gap-2">
                <Button icon="pi pi-refresh" severity="secondary" rounded :loading="loading" @click="loadAll" />
                <Button icon="pi pi-directions" :label="t('web.node_list.apply_gateway')" @click="openGatewayDialog()" />
            </div>
        </div>

        <div v-if="loading && nodes.length === 0" class="flex items-center justify-center py-16 text-gray-500 dark:text-gray-400">
            <ProgressSpinner />
        </div>

        <DataTable v-else :value="nodes" dataKey="machine_id" stripedRows responsiveLayout="scroll">
            <template #empty>
                <div class="py-8 text-center text-gray-500 dark:text-gray-400">{{ t('web.node_list.empty') }}</div>
            </template>

            <Column :header="t('web.node_list.node')">
                <template #body="slotProps">
                    <div class="flex flex-col gap-1">
                        <span class="font-medium text-gray-900 dark:text-gray-100">{{ nodeLabel(slotProps.data) }}</span>
                        <span class="font-mono text-xs text-gray-500 dark:text-gray-400">{{ slotProps.data.machine_id }}</span>
                    </div>
                </template>
            </Column>

            <Column :header="t('web.node_list.status')">
                <template #body="slotProps">
                    <div class="flex flex-wrap gap-2">
                        <Tag :severity="slotProps.data.machine_online ? 'success' : 'danger'"
                            :value="slotProps.data.machine_online ? t('web.node_list.machine_online') : t('web.node_list.machine_offline')" />
                        <Tag :severity="slotProps.data.agent.online ? 'success' : 'danger'"
                            :value="slotProps.data.agent.online ? t('web.node_list.agent_online') : t('web.node_list.agent_offline')" />
                    </div>
                </template>
            </Column>

            <Column :header="t('web.node_list.networks')">
                <template #body="slotProps">
                    <div class="flex flex-wrap gap-1">
                        <Tag v-for="networkId in slotProps.data.running_network_instances" :key="networkId"
                            severity="secondary" :value="shortId(networkId)" />
                        <span v-if="slotProps.data.running_network_instances.length === 0" class="text-sm text-gray-500 dark:text-gray-400">-</span>
                    </div>
                </template>
            </Column>

            <Column :header="t('web.node_list.agent_observed')">
                <template #body="slotProps">
                    <div class="flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-300">
                        <span>{{ slotProps.data.agent.easytier_ipv4 || t('web.node_list.no_easytier_ipv4') }}</span>
                        <span>{{ slotProps.data.agent.easytier_iface || '-' }}</span>
                        <span>{{ slotProps.data.agent.firewall_backend || '-' }}</span>
                    </div>
                </template>
            </Column>

            <Column :header="t('web.node_list.lan_scope')">
                <template #body="slotProps">
                    <div class="flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-300">
                        <span>{{ slotProps.data.agent.lan_cidrs.join(', ') || t('web.node_list.no_lan_cidr') }}</span>
                        <span>{{ slotProps.data.agent.ingress_ifaces.join(', ') || '-' }}</span>
                    </div>
                </template>
            </Column>

            <Column :header="t('web.node_list.policy')">
                <template #body="slotProps">
                    <div class="flex flex-col gap-1">
                        <Tag :severity="statusSeverity(slotProps.data.agent.policy_status)"
                            :value="slotProps.data.agent.policy_status || t('web.node_list.not_configured')" />
                        <span v-if="activePolicyForSource(slotProps.data.machine_id)" class="text-xs text-gray-500 dark:text-gray-400">
                            {{ shortId(activePolicyForSource(slotProps.data.machine_id)!.desired.exit_machine_id) }}
                        </span>
                        <span v-if="slotProps.data.agent.last_error" class="text-xs text-red-600 dark:text-red-300">
                            {{ slotProps.data.agent.last_error }}
                        </span>
                    </div>
                </template>
            </Column>

            <Column :header="t('web.node_list.actions')">
                <template #body="slotProps">
                    <div class="flex flex-col gap-1">
                        <div class="flex gap-2">
                            <Button icon="pi pi-directions" rounded size="small"
                                :disabled="sourceDisabledReason(slotProps.data) !== null"
                                @click="openGatewayDialog(slotProps.data)" />
                            <Button v-if="activePolicyForSource(slotProps.data.machine_id)" icon="pi pi-stop-circle"
                                rounded size="small" severity="secondary"
                                @click="disablePolicy(activePolicyForSource(slotProps.data.machine_id)!)" />
                        </div>
                        <span v-if="sourceDisabledReasonLabel(slotProps.data)"
                            class="max-w-48 text-xs leading-4 text-amber-600 dark:text-amber-300">
                            {{ sourceDisabledReasonLabel(slotProps.data) }}
                        </span>
                    </div>
                </template>
            </Column>
        </DataTable>

        <NodeGatewayDialog v-model:visible="dialogVisible" :api="api" :nodes="nodes"
            :source-machine-id="selectedSourceId" @applied="loadAll" />
    </div>
</template>
