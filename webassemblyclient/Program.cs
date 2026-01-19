using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.Extensions.Http;
using webassemblyclient;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Configure OIDC authentication
builder.Services.AddOidcAuthentication(options =>
{
    builder.Configuration.Bind("OidcProvider", options.ProviderOptions);
    options.ProviderOptions.Authority = "https://localhost:7179";
    options.ProviderOptions.ClientId = "webassemblyclient";
    options.ProviderOptions.ResponseType = "code";
    options.ProviderOptions.DefaultScopes.Add("openid");
    options.ProviderOptions.DefaultScopes.Add("profile");
    options.ProviderOptions.DefaultScopes.Add("email");
    options.ProviderOptions.DefaultScopes.Add("api");
    options.ProviderOptions.RedirectUri = builder.HostEnvironment.BaseAddress + "authentication/login-callback";
    options.ProviderOptions.PostLogoutRedirectUri = builder.HostEnvironment.BaseAddress + "authentication/logout-callback";
});


builder.Services.AddScoped<ApiAuthorizationMessageHandler>();

builder.Services.AddHttpClient("clientsapi", client =>
{
    client.BaseAddress = new Uri("https://localhost:7101");
})
.AddHttpMessageHandler<ApiAuthorizationMessageHandler>();

builder.Services.AddScoped(sp =>
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("clientsapi"));

await builder.Build().RunAsync();
