<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { Button, Dialog, Dropdown, InputSwitch, Textarea } from 'primevue';
import ApiClient, { type GatewayFullTunnelPolicy, type GatewayPolicySnapshot } from '../modules/api';

type DeviceOption = { label: string; value: string; networkIds: string[] };

const props = defineProps<{
    api?: ApiClient;
    visible: boolean;
    devices: DeviceOption[];
    policy?: GatewayPolicySnapshot | null;
}>();

const emit = defineEmits<{
    'update:visible': [value: boolean];
    saved: [];
}>();

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

watch(() => props.policy, (policy) => {
    if (policy) {
        policyId.value = policy.desired.policy_id;
        enabled.value = policy.desired.enabled;
        networkInstanceId.value = policy.desired.network_instance_id;
        sourceMachineId.value = policy.desired.source_machine_id;
        exitMachineId.value = policy.desired.exit_machine_id;
        managedCidrsText.value = policy.desired.managed_cidrs.join('\n');
        ingressIfacesText.value = policy.desired.ingress_ifaces.join('\n');
        includeDeviceTraffic.value = policy.desired.include_device_traffic;
        exitEgressMode.value = policy.desired.exit_egress.mode;
        exitEgressIface.value = policy.desired.exit_egress.iface || '';
    } else {
        policyId.value = newUuid();
        enabled.value = false;
        networkInstanceId.value = '';
        sourceMachineId.value = '';
        exitMachineId.value = '';
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
    if (ids.length === 1) {
        networkInstanceId.value = ids[0];
    } else if (!ids.includes(networkInstanceId.value)) {
        networkInstanceId.value = '';
    }
});

const errors = computed(() => {
    const result: string[] = [];
    if (!sourceMachineId.value) result.push('请选择入口节点');
    if (!exitMachineId.value) result.push('请选择出口节点');
    if (sourceMachineId.value && sourceMachineId.value === exitMachineId.value) result.push('入口节点和出口节点不能相同');
    if (sourceMachineId.value && exitMachineId.value && commonNetworkIds.value.length === 0) result.push('入口节点和出口节点没有共同的 EasyTier network instance');
    if (!networkInstanceId.value) result.push('请选择 EasyTier network instance id');
    const managedCidrs = managedCidrsText.value.split(/\s+/).filter(Boolean);
    if (managedCidrs.length === 0 && !includeDeviceTraffic.value) result.push('受管网段为空时必须包含设备自身流量');
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
    <Dialog :visible="visible" @update:visible="emit('update:visible', $event)" modal class="w-full md:w-2/5" :header="policy ? '编辑出口策略' : '创建出口策略'">
        <div class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <label class="text-sm text-gray-500">入口节点</label>
                    <Dropdown v-model="sourceMachineId" :options="devices" optionLabel="label" optionValue="value" class="w-full" />
                </div>
                <div>
                    <label class="text-sm text-gray-500">出口节点</label>
                    <Dropdown v-model="exitMachineId" :options="devices" optionLabel="label" optionValue="value" class="w-full" />
                </div>
            </div>
            <div>
                <label class="text-sm text-gray-500">Network Instance ID</label>
                <Dropdown v-model="networkInstanceId" :options="commonNetworkIds" class="w-full font-mono" placeholder="选择 source/exit 共同网络实例" />
            </div>
            <div>
                <label class="text-sm text-gray-500">受管网段，每行一个</label>
                <Textarea v-model="managedCidrsText" class="w-full font-mono" rows="3" placeholder="192.168.10.0/24" />
            </div>
            <div>
                <label class="text-sm text-gray-500">入口接口，可空，每行一个</label>
                <Textarea v-model="ingressIfacesText" class="w-full font-mono" rows="2" placeholder="br-lan" />
            </div>
            <div class="flex items-center gap-3">
                <InputSwitch v-model="includeDeviceTraffic" />
                <span>包含 R3S 自身普通出站流量</span>
            </div>
            <div class="flex items-center gap-3">
                <InputSwitch v-model="enabled" />
                <span>启用策略</span>
            </div>
            <div v-if="errors.length" class="text-sm text-red-600 space-y-1">
                <div v-for="error in errors" :key="error">{{ error }}</div>
            </div>
            <div v-if="saveError" class="text-sm text-red-600 break-all">{{ saveError }}</div>
        </div>
        <template #footer>
            <Button label="取消" severity="secondary" @click="emit('update:visible', false)" />
            <Button label="保存" icon="pi pi-save" :disabled="!canSave || saving" :loading="saving" @click="save" />
        </template>
    </Dialog>
</template>
