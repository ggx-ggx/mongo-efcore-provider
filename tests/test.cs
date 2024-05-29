using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

public class OktaSessionExample
{
    private static async Task<string> GetSessionTokenAsync(string username, string password, string oktaDomain)
    {
        using (var client = new HttpClient())
        {
            var content = new StringContent($"{{\"username\":\"{username}\",\"password\":\"{password}\"}}", Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"{oktaDomain}/api/v1/authn", content);
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();
            var json = JObject.Parse(responseContent);
            return json["sessionToken"].ToString();
        }
    }

    private static async Task<string> GetSessionIdAsync(string sessionToken, string oktaDomain)
    {
        using (var client = new HttpClient())
        {
            var content = new StringContent($"{{\"sessionToken\":\"{sessionToken}\"}}", Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"{oktaDomain}/api/v1/sessions", content);
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();
            var json = JObject.Parse(responseContent);
            return json["id"].ToString(); // This is the session ID
        }
    }

    private static async Task<JObject> GetTokensAsync(string sessionId, string clientId, string clientSecret, string oktaDomain, string redirectUri)
    {
        using (var client = new HttpClient())
        {
            var tokenEndpoint = $"{oktaDomain}/oauth2/default/v1/token";
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", sessionId),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
            });

            var response = await client.PostAsync(tokenEndpoint, content);
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();
            return JObject.Parse(responseContent);
        }
    }

    public static async Task Main(string[] args)
    {
        string username = "user@example.com";
        string password = "userpassword";
        string oktaDomain = "https://{yourOktaDomain}";
        string clientId = "{yourClientId}";
        string clientSecret = "{yourClientSecret}";
        string redirectUri = "{yourRedirectUri}";

        try
        {
            string sessionToken = await GetSessionTokenAsync(username, password, oktaDomain);
            string sessionId = await GetSessionIdAsync(sessionToken, oktaDomain);
            JObject tokens = await GetTokensAsync(sessionId, clientId, clientSecret, oktaDomain, redirectUri);

            string accessToken = tokens["access_token"].ToString();
            string refreshToken = tokens["refresh_token"].ToString();

            Console.WriteLine($"Access Token: {accessToken}");
            Console.WriteLine($"Refresh Token: {refreshToken}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

     public static async Task<JObject> ExchangeSessionIdForTokens(string sessionId, string oktaDomain, string clientId, string clientSecret, string redirectUri)
    {
        // Initialize HttpClientHandler to handle redirects manually
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false
        };

        using (var client = new HttpClient(handler))
        {
            // Step 1: Obtain Authorization Code using Session ID
            var authorizeUrl = $"{oktaDomain}/oauth2/default/v1/authorize?" +
                               $"client_id={clientId}&response_type=code&scope=openid%20profile%20email" +
                               $"&redirect_uri={redirectUri}&state=application_state&sessionToken={sessionId}";

            var authorizeResponse = await client.GetAsync(authorizeUrl);
            if (authorizeResponse.StatusCode != System.Net.HttpStatusCode.Found)
            {
                throw new Exception("Failed to obtain authorization code.");
            }

            var location = authorizeResponse.Headers.Location;
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(location.Query);
            if (!query.TryGetValue("code", out var authorizationCode))
            {
                throw new Exception("Authorization code not found in the response.");
            }

            // Step 2: Exchange Authorization Code for Access and Refresh Tokens
            var tokenEndpoint = $"{oktaDomain}/oauth2/default/v1/token";
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", authorizationCode),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
            });

            var tokenResponse = await client.PostAsync(tokenEndpoint, content);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                throw new Exception($"Token request failed: {errorContent}");
            }

            var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();
            return JObject.Parse(tokenResponseContent);
        }
    }
}

curl -X POST "https://<your_okta_domain>/oauth2/default/v1/token" \
-H "Accept: application/json" \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Cookie: sid=<your_session_id>" \
-d "grant_type=authorization_code" \
-d "redirect_uri=<your_redirect_uri>" \
-d "client_id=<your_client_id>" \
-d "client_secret=<your_client_secret>" \
-d "code=<authorization_code>"

    
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Start Okta Session</title>
    <script>
        async function startSession(accessToken) {
            const response = await fetch('https://<your_okta_domain>/api/v1/sessions/me', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include' // This is important to include session cookies
            });

            if (response.ok) {
                const sessionData = await response.json();
                console.log('Session started', sessionData);
            } else {
                console.error('Failed to start session', response.statusText);
            }
        }

        // Example usage: Replace 'yourAccessToken' with the actual access token
        startSession('yourAccessToken');
    </script>
</head>
<body>
    <h1>Okta Session Starter</h1>
</body>
</html>
