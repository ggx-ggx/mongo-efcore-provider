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



using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        // Assume this is your initial response with cookies
        HttpResponseMessage initialResponse = await GetInitialResponseAsync();

        // Extract cookies from the response
        CookieContainer cookieContainer = ExtractCookies(initialResponse);

        // Create a new HttpClient with the extracted cookies
        HttpClient clientWithCookies = CreateHttpClientWithCookies(cookieContainer);

        // Use the new HttpClient to make another request
        HttpResponseMessage newResponse = await clientWithCookies.GetAsync("https://your-target-url.com");

        // Output the result (for demonstration purposes)
        Console.WriteLine(await newResponse.Content.ReadAsStringAsync());
    }

    static async Task<HttpResponseMessage> GetInitialResponseAsync()
    {
        using (HttpClient client = new HttpClient())
        {
            // Make an initial request to get cookies
            HttpResponseMessage response = await client.GetAsync("https://your-initial-url.com");
            return response;
        }
    }

    static CookieContainer ExtractCookies(HttpResponseMessage response)
    {
        CookieContainer cookieContainer = new CookieContainer();

        if (response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            foreach (var header in setCookieHeaders)
            {
                var cookies = header.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
                string cookieName = null;
                string cookieValue = null;
                string domain = null;
                string path = "/";
                bool secure = false;
                bool httpOnly = false;

                foreach (var cookie in cookies)
                {
                    var parts = cookie.Split('=');

                    if (parts.Length == 2)
                    {
                        var name = parts[0].Trim();
                        var value = parts[1].Trim();

                        if (name.Equals("domain", StringComparison.OrdinalIgnoreCase))
                        {
                            domain = value;
                        }
                        else if (name.Equals("path", StringComparison.OrdinalIgnoreCase))
                        {
                            path = value;
                        }
                        else if (name.Equals("secure", StringComparison.OrdinalIgnoreCase))
                        {
                            secure = true;
                        }
                        else if (name.Equals("httponly", StringComparison.OrdinalIgnoreCase))
                        {
                            httpOnly = true;
                        }
                        else
                        {
                            cookieName = name;
                            cookieValue = value;
                        }
                    }
                }

                if (cookieName != null && cookieValue != null && domain != null)
                {
                    Cookie newCookie = new Cookie(cookieName, cookieValue, path, domain)
                    {
                        Secure = secure,
                        HttpOnly = httpOnly
                    };
                    cookieContainer.Add(newCookie);
                }
            }
        }

        return cookieContainer;
    }

    static HttpClient CreateHttpClientWithCookies(CookieContainer cookieContainer)
    {
        HttpClientHandler handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer
        };

        return new HttpClient(handler);
    }
}



using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

class LoggingHandler : DelegatingHandler
{
    public LoggingHandler(HttpMessageHandler innerHandler) : base(innerHandler) { }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Log the request
        Console.WriteLine("Request:");
        Console.WriteLine(request.ToString());
        if (request.Content != null)
        {
            Console.WriteLine(await request.Content.ReadAsStringAsync());
        }
        if (request.Headers.Contains("Cookie"))
        {
            Console.WriteLine("Cookies: " + string.Join("; ", request.Headers.GetValues("Cookie")));
        }

        // Send the request
        var response = await base.SendAsync(request, cancellationToken);

        // Log the response
        Console.WriteLine("Response:");
        Console.WriteLine(response.ToString());
        if (response.Content != null)
        {
            Console.WriteLine(await response.Content.ReadAsStringAsync());
        }

        return response;
    }
}

class Program
{
    static async Task Main(string[] args)
    {
        var handler = new LoggingHandler(new HttpClientHandler());
        var client = new HttpClient(handler);

        // Example request
        var request = new HttpRequestMessage(HttpMethod.Get, "https://httpbin.org/get");
        request.Headers.Add("Cookie", "exampleCookie=exampleValue");

        var response = await client.SendAsync(request);
        
        Console.WriteLine("Cookies received:");
        foreach (var cookie in response.Headers.GetValues("Set-Cookie"))
        {
            Console.WriteLine(cookie);
        }
    }
}

