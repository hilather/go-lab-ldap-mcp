import { Link, useLocation } from "react-router";

export function LaterTaskPage() {
  const location = useLocation();
  return (
    <main id="main">
      <h1>Page not found</h1>
      <p>
        <code>{location.pathname}</code> is not a LabLDAP operator route.
      </p>
      <p>
        <Link to="/">Return to the dashboard</Link>
      </p>
    </main>
  );
}
