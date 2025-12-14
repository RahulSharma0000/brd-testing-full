import { useEffect, useState } from "react";

export default function useDashboard(serviceCall, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    serviceCall()
      .then((res) => setData(res))
      .finally(() => setLoading(false));
  }, deps);

  return { data, loading };
}
