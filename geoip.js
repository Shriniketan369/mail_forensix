// ============================================================
// GEOIP LOOKUP MODULE
// Uses ipapi.co - free tier, HTTPS, CORS-enabled, no API key
// Limit: 1,000 requests/day - more than enough for a demo
// ============================================================

async function geoLookup(ip) {
  if (!ip) {
    return { error: 'No IP address available to look up.' };
  }

  // Skip private/local IPs - they won't resolve to real locations
  if (isPrivateIP(ip)) {
    return {
      ip,
      isPrivate: true,
      note: 'This is a private/internal IP address - no public geolocation available.',
    };
  }

  try {
    const response = await fetch(`https://ipapi.co/${ip}/json/`);

    if (!response.ok) {
      throw new Error(`GeoIP lookup failed (${response.status})`);
    }

    const data = await response.json();

    if (data.error) {
      return { ip, error: data.reason || 'GeoIP lookup returned an error.' };
    }

    return {
      ip,
      city: data.city,
      region: data.region,
      country: data.country_name,
      countryCode: data.country_code,
      isp: data.org,
      latitude: data.latitude,
      longitude: data.longitude,
      timezone: data.timezone,
    };
  } catch (err) {
    return { ip, error: err.message };
  }
}

function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;

  // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 127
  );
}

if (typeof module !== 'undefined') module.exports = { geoLookup };
