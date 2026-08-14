import { QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider } from "react-router";
import { createAppQueryClient } from "./lib/query";
import { RootPage } from "./routes/Root";

const queryClient = createAppQueryClient();

const router = createBrowserRouter([
  { path: "/", element: <RootPage /> },
  { path: "*", element: <RootPage /> },
]);

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
