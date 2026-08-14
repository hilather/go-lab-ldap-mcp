import { Link, useLocation } from "react-router";

export function LaterTaskPage() {
  const location = useLocation();
  return (
    <main id="main">
      <h1>Workflow not in this slice</h1>
      <p>
        <code>{location.pathname}</code> is reserved for a later task. User and group
        CRUD, search, and operator tools are not implemented here.
      </p>
      <p>
        <Link to="/">Return to the dashboard</Link>
      </p>
    </main>
  );
}
