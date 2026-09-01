import { notFound } from "next/navigation";
import { getApp, hasDefaultCredentials } from "@onecli/api/apps/registry";
import { checkOrgAppConfigExists } from "@/lib/actions/org-app-config";
import { AppDetail } from "@/app/(dashboard)/w/[workspaceId]/connections/_components/app-detail";

interface Props {
  params: Promise<{ provider: string; orgId: string }>;
}

const GlobalAppDetailPage = async ({ params }: Props) => {
  const { provider, orgId } = await params;
  const app = getApp(provider);
  if (!app) notFound();

  const hasEnvDefaults = hasDefaultCredentials(app);

  let hasAppConfig = false;
  try {
    hasAppConfig = await checkOrgAppConfigExists(provider);
  } catch {
    // Auth may not be resolved; treat as defaults
  }

  return (
    <AppDetail
      app={{
        id: app.id,
        name: app.name,
        icon: app.icon,
        darkIcon: app.darkIcon,
        description: app.description,
        connectionType: app.connectionMethod.type,
        blocklist: app.blocklist,
      }}
      configurable={app.configurable}
      hasEnvDefaults={hasEnvDefaults}
      hasAppConfig={hasAppConfig}
      pageScope="organization"
      backPath={`/org/${orgId}/global-connections`}
    />
  );
};

export default GlobalAppDetailPage;
