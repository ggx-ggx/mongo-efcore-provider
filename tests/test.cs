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
}
