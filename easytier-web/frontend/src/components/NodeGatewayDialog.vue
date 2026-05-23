<script setup lang="ts">
import { Button, Dialog, Dropdown, Tag, useToast } from 'primevue';
import { computed, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import ApiClient, { type GatewayNodeView } from '../modules/api';
import {
    exitDisabledReason,
    nodeLabel,
    sharedNetworkInstances,
    sourceDisabledReason,
    statusSeverity,
    type NodeDisabledReason,
} from './nodeListViewModel';

const props = defineProps<{
    api?: ApiClient,
    visible: boolean,
    nodes: GatewayNodeView[],
    sourceMachineId?: string | null,
}>();

const emit = defineEmits<{
    'update:visible': [value: boolean],
    applied: [],
}>();

const { t } = useI18n();
const toast = useToast();

const sourceMachineId = ref<string | null>(props.sourceMachineId || null);
const exitMachineId = ref<string | null>(null);
const selectedNetworkId = ref<string | null>(null);
const submitting = ref(false);

const dialogVisible = computed({
    get: () => props.visible,
    set: (value: boolean) => emit('update:visible', value),
});

const sourceNode = computed(() => props.nodes.find((node) => node.machine_id === sourceMachineId.value) || null);
const exitNode = computed(() => props.nodes.find((node) => node.machine_id === exitMachineId.value) || null);

const sourceOptions = computed(() => props.nodes.map((node) => ({
    label: nodeLabel(node),
    value: node.machine_id,
    disabled: sourceDisabledReason(node) !== null,
})));

const exitOptions = computed(() => props.nodes.map((node) => ({
    label: nodeLabel(node),
    value: node.machine_id,
    disabled: exitDisabledReason(node, sourceNode.value) !== null,
})));

const sharedNetworks = computed(() => sharedNetworkInstances(sourceNode.value, exitNode.value));

const networkOptions = computed(() => [
    { label: t('web.node_list.network_auto'), value: null },
    ...sharedNetworks.value.map((networkId) => ({ label: networkId, value: networkId })),
]);

const reasonLabel = (reason: NodeDisabledReason): string => {
    if (!reason) return '';
    return t(`web.node_list.reason_${reason}`);
};

const applyDisabledReason = computed<NodeDisabledReason>(() => {
    const sourceReason = sourceDisabledReason(sourceNode.value);
    if (sourceReason) return sourceReason;
    const exitReason = exitDisabledReason(exitNode.value, sourceNode.value);
    if (exitReason) return exitReason;
    return null;
});

const canApply = computed(() => (
    !!props.api
    && !!sourceNode.value
    && !!exitNode.value
    && applyDisabledReason.value === null
    && !submitting.value
));

watch(() => props.sourceMachineId, (value) => {
    sourceMachineId.value = value || null;
    exitMachineId.value = null;
    selectedNetworkId.value = null;
});

watch([sourceMachineId, exitMachineId], () => {
    selectedNetworkId.value = null;
});

const submit = async () => {
    if (!props.api || !sourceNode.value || !exitNode.value) return;
    submitting.value = true;
    try {
        const response = await props.api.quick_apply_gateway_policy({
            source_machine_id: sourceNode.value.machine_id,
            exit_machine_id: exitNode.value.machine_id,
            network_instance_id: selectedNetworkId.value,
            managed_cidrs_mode: 'auto',
            include_device_traffic: false,
        });
        toast.add({
            severity: 'success',
            summary: t('web.node_list.apply_success'),
            detail: response.selected_network_instance_id,
            life: 2500,
        });
        emit('applied');
        dialogVisible.value = false;
    } catch (e) {
        toast.add({ severity: 'error', summary: t('web.node_list.apply_failed'), detail: String(e), life: 4000 });
    } finally {
        submitting.value = false;
    }
};
</script>

<template>
    <Dialog v-model:visible="dialogVisible" modal :header="t('web.node_list.gateway_dialog_title')" class="w-full md:w-7/12">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="flex flex-col gap-2">
                <label class="text-sm font-medium text-gray-700 dark:text-gray-200">{{ t('web.node_list.source_node') }}</label>
                <Dropdown v-model="sourceMachineId" :options="sourceOptions" optionLabel="label" optionValue="value"
                    optionDisabled="disabled" class="w-full" />
                <div v-if="sourceNode" class="flex flex-wrap gap-2 text-sm text-gray-500 dark:text-gray-400">
                    <Tag :severity="statusSeverity(sourceNode.agent.policy_status)" :value="sourceNode.agent.policy_status || 'unknown'" />
                    <span>{{ sourceNode.agent.lan_cidrs.join(', ') || t('web.node_list.no_lan_cidr') }}</span>
                </div>
            </div>

            <div class="flex flex-col gap-2">
                <label class="text-sm font-medium text-gray-700 dark:text-gray-200">{{ t('web.node_list.exit_node') }}</label>
                <Dropdown v-model="exitMachineId" :options="exitOptions" optionLabel="label" optionValue="value"
                    optionDisabled="disabled" class="w-full" />
                <div v-if="exitNode" class="flex flex-wrap gap-2 text-sm text-gray-500 dark:text-gray-400">
                    <Tag :severity="exitNode.agent.online ? 'success' : 'danger'" :value="exitNode.agent.online ? t('web.node_list.agent_online') : t('web.node_list.agent_offline')" />
                    <span>{{ exitNode.agent.easytier_ipv4 || t('web.node_list.no_easytier_ipv4') }}</span>
                </div>
            </div>
        </div>

        <div class="mt-4 flex flex-col gap-2">
            <label class="text-sm font-medium text-gray-700 dark:text-gray-200">{{ t('web.node_list.network_instance') }}</label>
            <Dropdown v-model="selectedNetworkId" :options="networkOptions" optionLabel="label" optionValue="value" class="w-full" />
        </div>

        <div v-if="applyDisabledReason" class="mt-4 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
            {{ reasonLabel(applyDisabledReason) }}
        </div>

        <template #footer>
            <Button :label="t('web.common.cancel')" icon="pi pi-times" severity="secondary" text @click="dialogVisible = false" />
            <Button :label="t('web.node_list.apply_gateway')" icon="pi pi-send" :loading="submitting" :disabled="!canApply" @click="submit" />
        </template>
    </Dialog>
</template>

