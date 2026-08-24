const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export async function initiateDomainScan(domain) {
  try {
    const response = await fetch(`${API_BASE_URL}/domain/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ domain }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Scan request failed with status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.warn('API call error:', error);
    throw error;
  }
}

export async function getScanStatus(scanId) {
  const response = await fetch(`${API_BASE_URL}/domain/scan/${scanId}`);
  if (!response.ok) throw new Error('Failed to fetch scan status');
  return await response.json();
}

export async function getScanAssets(scanId, assetType = null) {
  const url = new URL(`${API_BASE_URL}/domain/scan/${scanId}/assets`, window.location.origin);
  if (assetType) url.searchParams.append('asset_type', assetType);
  const response = await fetch(url.toString());
  if (!response.ok) throw new Error('Failed to fetch scan assets');
  return await response.json();
}

export { API_BASE_URL };
