import { QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider } from "react-router";
import { LoginPage } from "./auth/LoginPage";
import { SessionGate } from "./auth/SessionGate";
import { createAppQueryClient } from "./lib/query";
import { DashboardPage } from "./routes/DashboardPage";
import { LaterTaskPage } from "./routes/LaterTaskPage";
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
