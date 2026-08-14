import { QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider } from "react-router";
import { LoginPage } from "./auth/LoginPage";
import { SessionGate } from "./auth/SessionGate";
import { createAppQueryClient } from "./lib/query";
import { GroupCreatePage } from "./routes/groups/GroupCreatePage";
import { GroupDetailPage } from "./routes/groups/GroupDetailPage";
import { GroupListPage } from "./routes/groups/GroupListPage";
import { AuditPage } from "./routes/audit/AuditPage";
import { AuthTestPage } from "./routes/auth-test/AuthTestPage";
import { DashboardPage } from "./routes/DashboardPage";
import { DiagnosticsPage } from "./routes/diagnostics/DiagnosticsPage";
import { ExportPage } from "./routes/export/ExportPage";
import { LaterTaskPage } from "./routes/LaterTaskPage";
import { ResetPage } from "./routes/reset/ResetPage";
import { SchemaPage } from "./routes/schema/SchemaPage";
import { SearchPage } from "./routes/search/SearchPage";
import { UserCreatePage } from "./routes/users/UserCreatePage";
import { UserDetailPage } from "./routes/users/UserDetailPage";
import { UserListPage } from "./routes/users/UserListPage";
import { AppShell } from "./shell/AppShell";

const queryClient = createAppQueryClient();

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    path: "/",
    element: <SessionGate />,
    children: [
      {
        element: <AppShell />,
        children: [
          { index: true, element: <DashboardPage /> },
          { path: "users", element: <UserListPage /> },
          { path: "users/new", element: <UserCreatePage /> },
          { path: "users/:id", element: <UserDetailPage /> },
          { path: "groups", element: <GroupListPage /> },
          { path: "groups/new", element: <GroupCreatePage /> },
          { path: "groups/:id", element: <GroupDetailPage /> },
          { path: "search", element: <SearchPage /> },
          { path: "auth-test", element: <AuthTestPage /> },
          { path: "schema", element: <SchemaPage /> },
          { path: "audit", element: <AuditPage /> },
          { path: "reset", element: <ResetPage /> },
          { path: "export", element: <ExportPage /> },
          { path: "diagnostics", element: <DiagnosticsPage /> },
          { path: "*", element: <LaterTaskPage /> },
        ],
      },
    ],
  },
]);

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
