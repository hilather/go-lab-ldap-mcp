import { Link, useLocation } from "react-router";

export function LaterTaskPage() {
  const location = useLocation();
  return (
    <main id="main">
      <h1>Workflow not in this slice</h1>
      <p>
        <code>{location.pathname}</code> is reserved for a later task. Search, bind
        test, schema, audit, reset, and export are not implemented here.
      </p>
      <p>
        <Link to="/">Return to the dashboard</Link>
      </p>
    </main>
  );
}
