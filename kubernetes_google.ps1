# ============================================================
# GKE Security Review Script
# Update the variables below for each engagement
# ============================================================

$CLUSTER = "*****-*****-***-**-***-**-****"
$REGION = "europe-west2"
$PROJECT = "*****-*****-***-**-****"
$OUT = "gke_review_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Namespaces to check for workload hardening
$NAMESPACES = @(
    "app"
    "app-backend"
)

# ============================================================
# Get full cluster describe once and store it
# ============================================================
$CLUSTER_DESC = gcloud container clusters describe $CLUSTER --region $REGION --format=yaml 2>&1

"=== GKE SECURITY REVIEW REPORT ===" | Tee-Object -FilePath $OUT -Append
"Cluster: $CLUSTER" | Tee-Object -FilePath $OUT -Append
"Project: $PROJECT" | Tee-Object -FilePath $OUT -Append
"Region:  $REGION" | Tee-Object -FilePath $OUT -Append
"Date:    $(Get-Date)" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

# ============================================================
# SECTION 1 - CLUSTER OVERVIEW
# ============================================================

"=== [1] CLUSTER INFO ===" | Tee-Object -FilePath $OUT -Append
kubectl cluster-info | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [2] CURRENT PERMISSIONS ===" | Tee-Object -FilePath $OUT -Append
kubectl auth can-i --list | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [3] ALL NAMESPACES ===" | Tee-Object -FilePath $OUT -Append
kubectl get namespaces | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [4] ALL NODES ===" | Tee-Object -FilePath $OUT -Append
kubectl get nodes -o wide | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [5] ALL PODS ===" | Tee-Object -FilePath $OUT -Append
kubectl get pods --all-namespaces -o wide | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [6] ALL SERVICES ===" | Tee-Object -FilePath $OUT -Append
kubectl get services --all-namespaces | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [7] SERVICES WITH EXTERNAL IPS - LOADBALANCER AND NODEPORT ===" | Tee-Object -FilePath $OUT -Append
kubectl get services --all-namespaces | Select-String -Pattern "LoadBalancer|NodePort" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [8] ALL DEPLOYMENTS ===" | Tee-Object -FilePath $OUT -Append
kubectl get deployments --all-namespaces | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [9] ALL INGRESS ===" | Tee-Object -FilePath $OUT -Append
kubectl get ingress --all-namespaces | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [10] ALL CONFIG MAPS ===" | Tee-Object -FilePath $OUT -Append
kubectl get configmaps --all-namespaces | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

# ============================================================
# SECTION 2 - KUBERNETES FINDINGS
# ============================================================

"=== [K01] KUBERNETES OUTDATED CLUSTER VERSION ===" | Tee-Object -FilePath $OUT -Append
"FAIL if node or master version behind latest stable channel default" | Tee-Object -FilePath $OUT -Append
kubectl version | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(currentMasterVersion,currentNodeVersion)" 2>&1 | Tee-Object -FilePath $OUT -Append
gcloud container node-pools list --cluster $CLUSTER --region $REGION --format="table(name,version)" 2>&1 | Tee-Object -FilePath $OUT -Append
gcloud container get-server-config --region $REGION --format="yaml(channels)" 2>&1 | Select-String -Pattern "defaultVersion" | Select-Object -First 4 | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(releaseChannel)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K02] KUBERNETES WEB UI DASHBOARD ENABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if dashboard pod or service exists" | Tee-Object -FilePath $OUT -Append
kubectl get pods --all-namespaces | Select-String -Pattern "dashboard" | Tee-Object -FilePath $OUT -Append
kubectl get services --all-namespaces | Select-String -Pattern "dashboard" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K03] KUBERNETES UNRESTRICTED CLUSTER NETWORK - NETWORK POLICIES ===" | Tee-Object -FilePath $OUT -Append
"FAIL if no network policies defined" | Tee-Object -FilePath $OUT -Append
kubectl get networkpolicies --all-namespaces | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K04] KUBERNETES POD OUTBOUND ACCESS TO EXTERNAL SERVICE - EGRESS ===" | Tee-Object -FilePath $OUT -Append
"FAIL if no egress rules defined in network policies" | Tee-Object -FilePath $OUT -Append
kubectl get networkpolicies --all-namespaces -o yaml | Select-String -Pattern "egress" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K05] KUBERNETES POD PUBLIC DNS RESOLUTION - OUTBOUND ACCESS ===" | Tee-Object -FilePath $OUT -Append
"FAIL if CoreDNS allows unrestricted external resolution" | Tee-Object -FilePath $OUT -Append
kubectl get configmap coredns -n kube-system -o yaml | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K06] KUBERNETES ROLE BINDING FOR UNAUTHENTICATED USERS ===" | Tee-Object -FilePath $OUT -Append
"FAIL if system:anonymous or system:unauthenticated has any bindings" | Tee-Object -FilePath $OUT -Append
kubectl get clusterrolebindings -o wide | Select-String -Pattern "system:anonymous|system:unauthenticated" | Tee-Object -FilePath $OUT -Append
kubectl get rolebindings --all-namespaces -o wide | Select-String -Pattern "system:anonymous|system:unauthenticated" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K07] KUBERNETES CLUSTER ADMIN BINDINGS ===" | Tee-Object -FilePath $OUT -Append
"FAIL if unexpected principals have cluster-admin" | Tee-Object -FilePath $OUT -Append
kubectl get clusterrolebindings -o wide | Select-String -Pattern "cluster-admin" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K08] KUBERNETES ALL CLUSTER ROLE BINDINGS ===" | Tee-Object -FilePath $OUT -Append
kubectl get clusterrolebindings -o wide | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K09] KUBERNETES ALL ROLE BINDINGS ===" | Tee-Object -FilePath $OUT -Append
kubectl get rolebindings --all-namespaces -o wide | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K10] KUBERNETES DEFAULT SERVICE ACCOUNT PERMISSIONS ===" | Tee-Object -FilePath $OUT -Append
"FAIL if default service account has any role bindings" | Tee-Object -FilePath $OUT -Append
kubectl get serviceaccounts --all-namespaces | Tee-Object -FilePath $OUT -Append
kubectl get clusterrolebindings -o wide | Select-String -Pattern "default" | Tee-Object -FilePath $OUT -Append
kubectl get rolebindings --all-namespaces -o wide | Select-String -Pattern "default" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K11] KUBERNETES SECRETS EXPOSED AS ENVIRONMENT VARIABLES ===" | Tee-Object -FilePath $OUT -Append
"FAIL if secretKeyRef found in pod env vars" | Tee-Object -FilePath $OUT -Append
kubectl get secrets --all-namespaces | Tee-Object -FilePath $OUT -Append
kubectl get pods --all-namespaces -o yaml | Select-String -Pattern "secretKeyRef" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K12] KUBERNETES POD SECURITY POLICY NOT IN USE ===" | Tee-Object -FilePath $OUT -Append
"FAIL if no PSP and no pod security admission labels on namespaces" | Tee-Object -FilePath $OUT -Append
kubectl get psp 2>&1 | Tee-Object -FilePath $OUT -Append
kubectl get namespaces -o yaml | Select-String -Pattern "pod-security" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K13] KUBERNETES CLUSTER WITHOUT DEFINED RESOURCE QUOTAS OR LIMITS ===" | Tee-Object -FilePath $OUT -Append
"FAIL if no resource quotas or limit ranges defined" | Tee-Object -FilePath $OUT -Append
kubectl get resourcequota --all-namespaces | Tee-Object -FilePath $OUT -Append
kubectl get limitrange --all-namespaces | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K14] KUBERNETES INSECURE PORT AVAILABLE ===" | Tee-Object -FilePath $OUT -Append
"FAIL if insecure-port is set and non-zero" | Tee-Object -FilePath $OUT -Append
kubectl get pods -n kube-system -o yaml | Select-String -Pattern "insecure-port|insecure-bind-address" | Tee-Object -FilePath $OUT -Append
gcloud compute firewall-rules list --format="table(name,direction,priority,sourceRanges,allowed)" | Select-String -Pattern "8080|8443" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [K15] KUBERNETES UNAUTHENTICATED SERVICE ACCESS FROM CLUSTER ===" | Tee-Object -FilePath $OUT -Append
"Review services below for any that may allow unauthenticated access" | Tee-Object -FilePath $OUT -Append
kubectl get services --all-namespaces -o wide | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

# ============================================================
# SECTION 3 - GKE SPECIFIC FINDINGS
# ============================================================

"=== [G01] GKE BASIC AUTHENTICATION ENABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if masterAuth contains username/password" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(masterAuth)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G02] GKE DEFAULT SERVICE ACCOUNT IN USE ===" | Tee-Object -FilePath $OUT -Append
"FAIL if node pools use default compute service account" | Tee-Object -FilePath $OUT -Append
gcloud container node-pools list --cluster $CLUSTER --region $REGION --format="table(name,config.serviceAccount)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G03] GKE CERTIFICATE AUTHENTICATION ENABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if issueClientCertificate: true" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(masterAuth.clientCertificateConfig)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G04] GKE LEGACY AUTHORIZATION ABAC ENABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if legacyAbac enabled: true" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(legacyAbac)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G05] GKE AUTOMATIC NODE UPGRADES DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if autoUpgrade: false on any node pool" | Tee-Object -FilePath $OUT -Append
gcloud container node-pools list --cluster $CLUSTER --region $REGION --format="table(name,management.autoUpgrade,management.autoRepair)" 2>&1 | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(nodePools.management)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G06] GKE LACK OF ACCESS SCOPES LIMITATION ===" | Tee-Object -FilePath $OUT -Append
"FAIL if oauthScopes contains cloud-platform" | Tee-Object -FilePath $OUT -Append
gcloud container node-pools list --cluster $CLUSTER --region $REGION --format="table(name,config.oauthScopes)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G07] GKE MASTER AUTHORIZED NETWORKS NOT ENABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if masterAuthorizedNetworksConfig enabled: false or missing" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(masterAuthorizedNetworksConfig)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G08] GKE ALIAS IP DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if useIpAliases: false or ipAllocationPolicy missing" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(ipAllocationPolicy)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G09] GKE POD SECURITY POLICY DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if podSecurityPolicyConfig enabled: false or unset" | Tee-Object -FilePath $OUT -Append
$result = gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(podSecurityPolicyConfig)" 2>&1
if ([string]::IsNullOrWhiteSpace($result)) { "UNSET" | Tee-Object -FilePath $OUT -Append } else { $result | Tee-Object -FilePath $OUT -Append }
"" | Tee-Object -FilePath $OUT -Append

"=== [G10] GKE PRIVATE CLUSTER DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if enablePrivateNodes: false or enablePublicEndpoint: true" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(controlPlaneEndpointsConfig,privateClusterConfig)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G11] GKE CLUSTERS LACKING LABELS ===" | Tee-Object -FilePath $OUT -Append
"FAIL if resourceLabels is empty or missing" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(resourceLabels)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G12] GKE NODES OUT OF DATE AND VULNERABLE ===" | Tee-Object -FilePath $OUT -Append
"FAIL if node version behind master or latest stable channel default" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(currentMasterVersion,currentNodeVersion)" 2>&1 | Tee-Object -FilePath $OUT -Append
gcloud container node-pools list --cluster $CLUSTER --region $REGION --format="table(name,version)" 2>&1 | Tee-Object -FilePath $OUT -Append
gcloud container get-server-config --region $REGION --format="yaml(channels)" 2>&1 | Select-String -Pattern "defaultVersion" | Select-Object -First 4 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G13] GKE CLUSTER LOGGING DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if loggingService: none" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(loggingConfig,loggingService)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G14] GKE WORKLOAD IDENTITY DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if workloadIdentityConfig missing or workloadPool not set" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(workloadIdentityConfig)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G15] GKE METADATA SERVER DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if workloadMetadataConfig mode not set to GKE_METADATA" | Tee-Object -FilePath $OUT -Append
gcloud container node-pools list --cluster $CLUSTER --region $REGION --format="table(name,config.workloadMetadataConfig.mode)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G16] GKE SHIELDED NODES DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if shieldedNodes enabled: false or secureBoot/integrityMonitoring disabled" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(shieldedNodes)" 2>&1 | Tee-Object -FilePath $OUT -Append
gcloud container node-pools list --cluster $CLUSTER --region $REGION --format="table(name,config.shieldedInstanceConfig.enableSecureBoot,config.shieldedInstanceConfig.enableIntegrityMonitoring)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G17] GKE CLUSTER INTRANODE VISIBILITY DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if enableIntraNodeVisibility: false or missing" | Tee-Object -FilePath $OUT -Append
$result = gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(networkConfig.enableIntraNodeVisibility)" 2>&1
if ([string]::IsNullOrWhiteSpace($result)) { "UNSET" | Tee-Object -FilePath $OUT -Append } else { $result | Tee-Object -FilePath $OUT -Append }
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(networkConfig)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G18] GKE CLUSTER BINARY AUTHORIZATION DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if binaryAuthorization empty or evaluationMode: DISABLED" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(binaryAuthorization)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [G19] GKE APPLICATION LAYER SECRETS ENCRYPTION DISABLED ===" | Tee-Object -FilePath $OUT -Append
"FAIL if databaseEncryption state: DECRYPTED or keyName missing" | Tee-Object -FilePath $OUT -Append
gcloud container clusters describe $CLUSTER --region $REGION --format="yaml(databaseEncryption)" 2>&1 | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

# ============================================================
# SECTION 4 - GCP PLATFORM FINDINGS
# ============================================================

"=== [P01] GCP FIREWALL RULES - PERMISSIVE FILTERING ===" | Tee-Object -FilePath $OUT -Append
"FAIL if any rule allows 0.0.0.0/0 on sensitive ports" | Tee-Object -FilePath $OUT -Append
gcloud compute firewall-rules list --format="table(name,direction,priority,sourceRanges,allowed)" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [P02] GCP IAM POLICY ===" | Tee-Object -FilePath $OUT -Append
"FAIL if primitive roles owner/editor assigned to users or service accounts" | Tee-Object -FilePath $OUT -Append
gcloud projects get-iam-policy $PROJECT | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

"=== [P03] GCP SERVICE ACCOUNTS ===" | Tee-Object -FilePath $OUT -Append
gcloud iam service-accounts list | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

# ============================================================
# SECTION 5 - WORKLOAD HARDENING (SCOPED NAMESPACES ONLY)
# ============================================================

"=== [W01] KUBERNETES WORKLOAD HARDENING - SECURITY CONTEXT CHECK ===" | Tee-Object -FilePath $OUT -Append
"Checking namespaces: $($NAMESPACES -join ', ')" | Tee-Object -FilePath $OUT -Append
"" | Tee-Object -FilePath $OUT -Append

foreach ($NS in $NAMESPACES) {
    "=== Namespace: $NS ===" | Tee-Object -FilePath $OUT -Append

    $DEPLOYMENTS = kubectl get deployments -n $NS -o custom-columns="NAME:.metadata.name" --no-headers 2>&1

    foreach ($NAME in $DEPLOYMENTS) {
        $NAME = $NAME.Trim()
        if ([string]::IsNullOrWhiteSpace($NAME)) { continue }

        "--- [$NS] $NAME - security context ---" | Tee-Object -FilePath $OUT -Append
        kubectl get deployment $NAME -n $NS -o yaml | Select-String -Pattern "securityContext" -Context 0,10 | Tee-Object -FilePath $OUT -Append

        "--- [$NS] $NAME - privilege and capability checks ---" | Tee-Object -FilePath $OUT -Append
        kubectl get deployment $NAME -n $NS -o yaml | Select-String -Pattern "privileged|hostPID|hostNetwork|hostIPC|allowPrivilegeEscalation|runAsNonRoot|runAsUser|readOnlyRootFilesystem|capabilities" | Tee-Object -FilePath $OUT -Append

        "--- [$NS] $NAME - resource limits ---" | Tee-Object -FilePath $OUT -Append
        kubectl get deployment $NAME -n $NS -o yaml | Select-String -Pattern "resources" -Context 0,8 | Tee-Object -FilePath $OUT -Append

        "--- [$NS] $NAME - volume mounts ---" | Tee-Object -FilePath $OUT -Append
        kubectl get deployment $NAME -n $NS -o yaml | Select-String -Pattern "volumeMounts" -Context 0,10 | Tee-Object -FilePath $OUT -Append

        "--- [$NS] $NAME - environment variables ---" | Tee-Object -FilePath $OUT -Append
        kubectl get deployment $NAME -n $NS -o yaml | Select-String -Pattern "env:" -Context 0,15 | Tee-Object -FilePath $OUT -Append

        "--- [$NS] $NAME - service account and automount ---" | Tee-Object -FilePath $OUT -Append
        kubectl get deployment $NAME -n $NS -o yaml | Select-String -Pattern "serviceAccount|automountServiceAccount" -Context 0,3 | Tee-Object -FilePath $OUT -Append

        "--- [$NS] $NAME - full spec ---" | Tee-Object -FilePath $OUT -Append
        kubectl get deployment $NAME -n $NS -o yaml | Tee-Object -FilePath $OUT -Append

        "" | Tee-Object -FilePath $OUT -Append
    }
}

Write-Host "=== COMPLETE - Output saved to $OUT ===" -ForegroundColor Green
