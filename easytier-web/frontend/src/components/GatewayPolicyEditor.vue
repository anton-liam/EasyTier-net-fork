<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { Button, Dialog, Dropdown, InputSwitch, Message, Textarea } from 'primevue';
import { useI18n } from 'vue-i18n';
import ApiClient, { type GatewayFullTunnelPolicy, type GatewayPolicySnapshot } from '../modules/api';

type DeviceOption = { label: string; value: string; networkIds: string[] };

const props = defineProps<{
    api?: ApiClient;
    visible: boolean;
    devices: DeviceOption[];
    policy?: GatewayPolicySnapshot | null;
    initialSourceMachineId?: string;
    initialExitMachineId?: string;
    initialNetworkInstanceId?: string;
}>();

const emit = defineEmits<{
    'update:visible': [value: boolean];
    saved: [];
}>();

const { t } = useI18n();

const newUuid = () => {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

const policyId = ref<string>(newUuid());
const enabled = ref(false);
const networkInstanceId = ref('');
const sourceMachineId = ref('');
const exitMachineId = ref('');
const managedCidrsText = ref('');
const ingressIfacesText = ref('');
const includeDeviceTraffic = ref(true);
const exitEgressMode = ref<'auto' | 'interface'>('auto');
const exitEgressIface = ref('');
const saving = ref(false);
const saveError = ref('');

watch(() => [props.policy, props.initialSourceMachineId, props.initialExitMachineId, props.initialNetworkInstanceId, props.visible], ([policy]) => {
    if (policy) {
        const snapshot = policy as GatewayPolicySnapshot;
        policyId.value = snapshot.desired.policy_id;
        enabled.value = snapshot.desired.enabled;
        networkInstanceId.value = snapshot.desired.network_instance_id;
        sourceMachineId.value = snapshot.desired.source_machine_id;
        exitMachineId.value = snapshot.desired.exit_machine_id;
        managedCidrsText.value = snapshot.desired.managed_cidrs.join('\n');
        ingressIfacesText.value = snapshot.desired.ingress_ifaces.join('\n');
        includeDeviceTraffic.value = snapshot.desired.include_device_traffic;
        exitEgressMode.value = snapshot.desired.exit_egress.mode;
        exitEgressIface.value = snapshot.desired.exit_egress.iface || '';
    } else {
        policyId.value = newUuid();
        enabled.value = false;
        networkInstanceId.value = '';
        sourceMachineId.value = props.initialSourceMachineId || '';
        exitMachineId.value = props.initialExitMachineId || '';
        networkInstanceId.value = props.initialNetworkInstanceId || '';
        managedCidrsText.value = '';
        ingressIfacesText.value = '';
        includeDeviceTraffic.value = true;
        exitEgressMode.value = 'auto';
        exitEgressIface.value = '';
    }
    saveError.value = '';
}, { immediate: true });

const sourceDevice = computed(() => props.devices.find((device) => device.value === sourceMachineId.value));
const exitDevice = computed(() => props.devices.find((device) => device.value === exitMachineId.value));
const exitDeviceOptions = computed(() => {
    const networkId = networkInstanceId.value || props.initialNetworkInstanceId || '';
    return props.devices.filter((device) => (
        device.value !== sourceMachineId.value
        && (!networkId || device.networkIds.includes(networkId))
    ));
});
const commonNetworkIds = computed(() => {
    const sourceIds = new Set(sourceDevice.value?.networkIds || []);
    const ids = (exitDevice.value?.networkIds || []).filter((id) => sourceIds.has(id));
    if (
        props.policy
        && props.policy.desired.source_machine_id === sourceMachineId.value
        && props.policy.desired.exit_machine_id === exitMachineId.value
        && !ids.includes(props.policy.desired.network_instance_id)
    ) {
        ids.push(props.policy.desired.network_instance_id);
    }
    return ids;
});

watch(commonNetworkIds, (ids) => {
    if (props.initialNetworkInstanceId && ids.includes(props.initialNetworkInstanceId)) {
        networkInstanceId.value = props.initialNetworkInstanceId;
    } else if (ids.length === 1) {
        networkInstanceId.value = ids[0];
    } else if (!ids.includes(networkInstanceId.value)) {
        networkInstanceId.value = '';
    }
});

watch([exitDeviceOptions, () => props.visible], ([options]) => {
    if (!props.visible || props.policy || exitMachineId.value) return;
    if (options.length === 1) {
        exitMachineId.value = options[0].value;
    }
});

const errors = computed(() => {
    const result: string[] = [];
    if (!sourceMachineId.value) result.push(t('web.gateway_policy.error_select_source'));
    if (!exitMachineId.value) result.push(t('web.gateway_policy.error_select_exit'));
    if (sourceMachineId.value && sourceMachineId.value === exitMachineId.value) result.push(t('web.gateway_policy.error_same_source_exit'));
    if (sourceMachineId.value && exitMachineId.value && commonNetworkIds.value.length === 0) result.push(t('web.gateway_policy.error_no_common_network'));
    if (!networkInstanceId.value) result.push(t('web.gateway_policy.error_select_network'));
    const managedCidrs = managedCidrsText.value.split(/\s+/).filter(Boolean);
    if (managedCidrs.length === 0 && !includeDeviceTraffic.value) result.push(t('web.gateway_policy.error_empty_scope'));
    return result;
});

const canSave = computed(() => errors.value.length === 0 && !!props.api);

const buildPayload = (): GatewayFullTunnelPolicy => ({
    policy_id: policyId.value,
    enabled: enabled.value,
    network_instance_id: networkInstanceId.value,
    source_machine_id: sourceMachineId.value,
    managed_cidrs: managedCidrsText.value.split(/\s+/).filter(Boolean),
    ingress_ifaces: ingressIfacesText.value.split(/\s+/).filter(Boolean),
    include_device_traffic: includeDeviceTraffic.value,
    exit_machine_id: exitMachineId.value,
    exit_egress: {
        mode: exitEgressMode.value,
        iface: exitEgressMode.value === 'interface' ? exitEgressIface.value || null : null,
    },
    desired_version: (props.policy?.desired.desired_version || 0) + 1,
    protect_control_plane: true,
    healthcheck: {
        control_plane_timeout_seconds: 5,
        exit_timeout_seconds: 10,
    },
    rollback: {
        enabled: true,
        max_fail_seconds: 30,
    },
});

const save = async () => {
    if (!props.api || !canSave.value) return;
    saving.value = true;
    saveError.value = '';
    try {
        await props.api.upsert_gateway_policy(buildPayload());
        emit('saved');
        emit('update:visible', false);
    } catch (e) {
        saveError.value = String(e);
    } finally {
        saving.value = false;
    }
};
</script>

<template>
    <Dialog :visible="visible" @update:visible="emit('update:visible', $event)" modal class="w-full md:w-7/12 lg:w-5/12" :header="policy ? t('web.gateway_policy.edit_policy') : t('web.gateway_policy.create_policy')">
        <div class="flex flex-col gap-4">
            <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div class="field">
                    <label>{{ t('web.gateway_policy.source_node') }}</label>
                    <Dropdown v-model="sourceMachineId" :options="devices" optionLabel="label" optionValue="value" class="w-full" />
                </div>
                <div class="field">
                    <label>{{ t('web.gateway_policy.exit_node') }}</label>
                    <Dropdown v-model="exitMachineId" :options="exitDeviceOptions" optionLabel="label" optionValue="value" class="w-full" />
                </div>
            </div>
            <div class="field">
                <label>{{ t('web.gateway_policy.network_instance_id') }}</label>
                <Dropdown v-model="networkInstanceId" :options="commonNetworkIds" class="w-full font-mono" :placeholder="t('web.gateway_policy.select_common_network')" />
            </div>
            <div class="field">
                <label>{{ t('web.gateway_policy.managed_cidrs') }}</label>
                <Textarea v-model="managedCidrsText" class="w-full font-mono" rows="3" placeholder="192.168.10.0/24" />
            </div>
            <div class="field">
                <label>{{ t('web.gateway_policy.ingress_ifaces') }}</label>
                <Textarea v-model="ingressIfacesText" class="w-full font-mono" rows="2" placeholder="br-lan" />
            </div>
            <div class="flex items-center gap-3">
                <InputSwitch v-model="includeDeviceTraffic" />
                <span>{{ t('web.gateway_policy.include_device_traffic') }}</span>
            </div>
            <div class="flex items-center gap-3">
                <InputSwitch v-model="enabled" />
                <span>{{ t('web.gateway_policy.enable_policy') }}</span>
            </div>
            <Message v-if="errors.length" severity="warn" :closable="false">
                <div v-for="error in errors" :key="error">{{ error }}</div>
            </Message>
            <Message v-if="saveError" severity="error" :closable="false">{{ saveError }}</Message>
        </div>
        <template #footer>
            <Button :label="t('web.common.cancel')" severity="secondary" @click="emit('update:visible', false)" />
            <Button :label="t('web.common.save')" icon="pi pi-save" :disabled="!canSave || saving" :loading="saving" @click="save" />
        </template>
    </Dialog>
</template>
