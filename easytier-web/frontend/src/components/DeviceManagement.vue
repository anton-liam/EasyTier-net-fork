<script setup lang="ts">
import { NetworkTypes, Utils, Api, RemoteManagement } from 'easytier-frontend-lib';
import { Button, Message } from 'primevue';
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import ApiClient, { type GatewayPolicySnapshot } from '../modules/api';
import GatewayPolicyEditor from './GatewayPolicyEditor.vue';
import GatewayPolicyTopology from './GatewayPolicyTopology.vue';


const props = defineProps<{
    api: ApiClient;
    deviceList: Array<Utils.DeviceInfo> | undefined;
}>();

const emits = defineEmits(['update']);

const { t } = useI18n();
const route = useRoute();
const router = useRouter();

const deviceId = computed<string>(() => {
    return route.params.deviceId as string;
});

const instanceId = computed<string>(() => {
    return route.params.instanceId as string;
});

const deviceInfo = computed<Utils.DeviceInfo | undefined | null>(() => {
    return deviceId.value ? props.deviceList?.find((device) => device.machine_id === deviceId.value) : null;
});

const selectedInstanceId = computed({
    get() {
        return instanceId.value;
    },
    set(value: string) {
        console.log("selectedInstanceId", value);
        router.push({ name: 'deviceManagement', params: { deviceId: deviceId.value, instanceId: value } });
    }
});

const remoteClient = computed<Api.RemoteClient>(() => props.api.get_remote_client(deviceId.value));
const gatewayPolicyEditorVisible = ref(false);
const gatewayPolicyTopologyVisible = ref(false);
const editingGatewayPolicy = ref<GatewayPolicySnapshot | null>(null);
const topologyGatewayPolicy = ref<GatewayPolicySnapshot | null>(null);
const gatewayPolicies = ref<GatewayPolicySnapshot[]>([]);
const selectedGatewayNetworkId = ref('');
const selectedGatewayNetworkInfo = ref<NetworkTypes.NetworkInstance | null>(null);

const newConfigGenerator = () => {
    const config = NetworkTypes.DEFAULT_NETWORK_CONFIG();
    config.hostname = deviceInfo.value?.hostname;
    return config;
}

type GatewayPolicyActionContext = {
    instanceId?: string;
    networkInfo?: NetworkTypes.NetworkInstance | null;
    running?: boolean;
    errorMessage?: string;
};

const shortId = (value?: string | null) => value ? value.slice(0, 8) : '-';

const gatewayDeviceOptions = computed(() => (props.deviceList || [])
    .filter((device) => !!device.machine_id)
    .map((device) => ({
        label: `${device.hostname || 'EasyTier'} (${shortId(device.machine_id)})`,
        value: device.machine_id,
        hostname: device.hostname,
        publicIp: device.public_ip,
        networkIds: device.running_network_instances || [],
    })));

const controlHost = computed(() => {
    const apiHost = route.params.apiHost as string | undefined;
    if (!apiHost) return '';
    try {
        return new URL(atob(apiHost)).hostname;
    } catch {
        return '';
    }
});

const exitCandidateCount = (instanceId?: string) => {
    if (!instanceId) return 0;
    return gatewayDeviceOptions.value.filter((device) => (
        device.value !== deviceId.value && device.networkIds.includes(instanceId)
    )).length;
};

const gatewayPolicyDisabledReason = (ctx: GatewayPolicyActionContext) => {
    if (!deviceInfo.value) return t('web.gateway_policy.disabled_not_connected');
    if (!ctx.instanceId) return t('web.gateway_policy.disabled_select_network');
    if (!ctx.running) return t('web.gateway_policy.disabled_network_not_running');
    if (ctx.errorMessage) return t('web.gateway_policy.disabled_network_error', { error: ctx.errorMessage });
    if (!deviceInfo.value.running_network_instances?.includes(ctx.instanceId)) return t('web.gateway_policy.disabled_node_not_in_network');
    if (exitCandidateCount(ctx.instanceId) === 0) return t('web.gateway_policy.disabled_no_exit_peer');
    return '';
};

const canOpenGatewayPolicy = (ctx: GatewayPolicyActionContext) => gatewayPolicyDisabledReason(ctx) === '';

const selectGatewayPolicy = (policies: GatewayPolicySnapshot[], sourceMachineId: string, networkInstanceId: string) => (
    policies
        .filter((policy) => (
            policy.desired.source_machine_id === sourceMachineId
            && policy.desired.network_instance_id === networkInstanceId
        ))
        .sort((left, right) => {
            if (left.desired.enabled !== right.desired.enabled) return left.desired.enabled ? -1 : 1;
            return right.desired.desired_version - left.desired.desired_version;
        })[0] || null
);

const openGatewayPolicyEditor = async (ctx: GatewayPolicyActionContext) => {
    if (!ctx.instanceId || !canOpenGatewayPolicy(ctx)) return;
    selectedGatewayNetworkId.value = ctx.instanceId;
    selectedGatewayNetworkInfo.value = ctx.networkInfo || null;
    gatewayPolicies.value = await props.api.list_gateway_policies();
    editingGatewayPolicy.value = selectGatewayPolicy(gatewayPolicies.value, deviceId.value, ctx.instanceId);
    gatewayPolicyEditorVisible.value = true;
};

const openGatewayTopology = async (ctx: GatewayPolicyActionContext) => {
    if (!ctx.instanceId || !canOpenGatewayPolicy(ctx)) return;
    selectedGatewayNetworkId.value = ctx.instanceId;
    selectedGatewayNetworkInfo.value = ctx.networkInfo || null;
    gatewayPolicies.value = await props.api.list_gateway_policies();
    topologyGatewayPolicy.value = selectGatewayPolicy(gatewayPolicies.value, deviceId.value, ctx.instanceId);
    gatewayPolicyTopologyVisible.value = true;
};

</script>

<template>
    <RemoteManagement :api="remoteClient" v-model:instance-id="selectedInstanceId"
        :new-config-generator="newConfigGenerator">
        <template #network-status-actions="slotProps">
            <div class="mb-4 border border-surface-200 bg-surface-50 p-3">
                <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                    <div>
                        <div class="font-medium">{{ t('web.gateway_policy.title') }}</div>
                        <div class="text-sm text-secondary">
                            {{ t('web.gateway_policy.description') }}
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <Button icon="pi pi-sitemap" :label="t('web.gateway_policy.topology_button')" severity="secondary"
                            :disabled="!canOpenGatewayPolicy(slotProps)"
                            @click="openGatewayTopology(slotProps)" />
                        <Button icon="pi pi-share-alt" :label="t('web.gateway_policy.configure_button')" severity="secondary"
                            :disabled="!canOpenGatewayPolicy(slotProps)"
                            @click="openGatewayPolicyEditor(slotProps)" />
                    </div>
                </div>
                <Message v-if="!canOpenGatewayPolicy(slotProps)" severity="warn" :closable="false" class="mt-3">
                    {{ gatewayPolicyDisabledReason(slotProps) }}
                </Message>
            </div>
        </template>
    </RemoteManagement>

    <GatewayPolicyEditor
        v-model:visible="gatewayPolicyEditorVisible"
        :api="api"
        :devices="gatewayDeviceOptions"
        :policy="editingGatewayPolicy"
        :initial-source-machine-id="deviceId"
        :initial-network-instance-id="selectedGatewayNetworkId"
        @saved="emits('update')"
    />

    <GatewayPolicyTopology
        v-model:visible="gatewayPolicyTopologyVisible"
        :api="api"
        :devices="gatewayDeviceOptions"
        :policy="topologyGatewayPolicy"
        :source-machine-id="deviceId"
        :network-instance-id="selectedGatewayNetworkId"
        :network-info="selectedGatewayNetworkInfo"
        :control-host="controlHost"
    />
</template>

<style scoped>
.device-management {
    height: 100%;
    display: flex;
    flex-direction: column;
}

.network-content {
    flex: 1;
    overflow-y: auto;
}

/* Button layout */
.button-container {
    gap: 0.5rem;
}

.create-button {
    font-weight: 600;
    min-width: 3rem;
}

/* Menu layout */
:deep(.p-menu) {
    min-width: 12rem;
    box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
    padding: 0.25rem;
}

:deep(.p-menu .p-menuitem) {
    border-radius: 0.25rem;
}

:deep(.p-menu .p-menuitem-link) {
    padding: 0.65rem 1rem;
    font-size: 0.9rem;
}

:deep(.p-menu .p-menuitem-icon) {
    margin-right: 0.75rem;
}

:deep(.p-menu .p-menuitem.p-error .p-menuitem-text,
    .p-menu .p-menuitem.p-error .p-menuitem-icon) {
    color: var(--red-500);
}

:deep(.p-menu .p-menuitem:hover.p-error .p-menuitem-link) {
    background-color: var(--red-50);
}

/* Icon button layout */
:deep(.p-button-icon-only) {
    width: 2.5rem !important;
    padding: 0.5rem !important;
}

:deep(.p-button-icon-only .p-button-icon) {
    font-size: 1rem;
}

/* Network selector layout */
.network-label {
    white-space: nowrap;
}

:deep(.network-select-container) {
    max-width: 100%;
}

/* Dark mode adaptations */
:deep(.bg-surface-50) {
    background-color: var(--surface-50, #f8fafc);
}

:deep(.bg-surface-0) {
    background-color: var(--surface-card, #ffffff);
}

:deep(.text-primary) {
    color: var(--primary-color, #3b82f6);
}

:deep(.text-secondary) {
    color: var(--text-color-secondary, #64748b);
}

@media (prefers-color-scheme: dark) {
    :deep(.bg-surface-50) {
        background-color: var(--surface-ground, #0f172a);
    }

    :deep(.bg-surface-0) {
        background-color: var(--surface-card, #1e293b);
    }
}

/* Responsive design for mobile devices */
@media (max-width: 768px) {
    .network-header {
        padding: 0.75rem;
    }

    .network-content {
        padding: 0.75rem;
    }

    /* Keep network labels compact on small screens */
    .network-label {
        font-size: 0.9rem;
    }
}
</style>
