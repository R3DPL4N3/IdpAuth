using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Http;
using OpenIddict.Abstractions;
using openiddictapi;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Configure Entity Framework Core
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

// Configure Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure primary HTTP message handler for HttpClientFactory to use HttpClientHandler
// This ensures OpenIddict uses HttpClientHandler instead of the default SocketsHttpHandler
builder.Services.Configure<HttpClientFactoryOptions>(options =>
{
    options.HttpMessageHandlerBuilderActions.Add(builder =>
    {
        builder.PrimaryHandler = new HttpClientHandler();
    });
});

// Configure OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        // Enable the authorization, token, introspection, and userinfo endpoints
        options.SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetIntrospectionEndpointUris("/connect/introspect")
            .SetUserInfoEndpointUris("/connect/userinfo");

        // Enable authorization code flow with PKCE
        options.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange();

        // Enable client credentials flow (for introspection)
        options.AllowClientCredentialsFlow();

        // Register signing and encryption credentials
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        // Register ASP.NET Core host and configure options
        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough();

        // Use reference tokens (opaque tokens)
        options.UseReferenceAccessTokens()
            .UseReferenceRefreshTokens();
    })
    .AddValidation(options =>
    {
        options.UseSystemNetHttp();
        options.UseIntrospection()
            .SetClientId("clientsapi")
            .SetClientSecret("clientsapi-secret");
        options.SetIssuer(new Uri("https://localhost:7179/"));
        options.UseAspNetCore();
    });

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("https://localhost:7121", "http://localhost:5048")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// Seed initial data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    context.Database.EnsureCreated();

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

    // Create roles
    if (!await roleManager.RoleExistsAsync("Admin"))
    {
        await roleManager.CreateAsync(new IdentityRole("Admin"));
    }

    // Create test user
    if (await userManager.FindByNameAsync("testuser") == null)
    {
        var user = new IdentityUser { UserName = "testuser", Email = "test@example.com" };
        await userManager.CreateAsync(user, "Test123!");
    }

    // Register WebAssembly client application
    if (await manager.FindByClientIdAsync("webassemblyclient") == null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "webassemblyclient",
            DisplayName = "WebAssembly Client",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            RedirectUris =
            {
                new Uri("https://localhost:7121/authentication/login-callback"),
                new Uri("http://localhost:5048/authentication/login-callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:7121/authentication/logout-callback"),
                new Uri("http://localhost:5048/authentication/logout-callback")
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "api"
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        });
    }

    // Register Clients API application (for introspection)
    if (await manager.FindByClientIdAsync("clientsapi") == null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "clientsapi",
            ClientSecret = "clientsapi-secret",
            DisplayName = "Clients API",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Introspection
            }
        });
    }

    // Register OpenID Connect scopes used by the client.
    if (await scopeManager.FindByNameAsync("openid") == null)
    {
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "openid",
            DisplayName = "OpenID",
        });
    }

    if (await scopeManager.FindByNameAsync("profile") == null)
    {
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "profile",
            DisplayName = "User profile"
        });
    }

    if (await scopeManager.FindByNameAsync("email") == null)
    {
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "email",
            DisplayName = "User email"
        });
    }

    if (await scopeManager.FindByNameAsync("roles") == null)
    {
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "roles",
            DisplayName = "User roles"
        });
    }

    // Update or create the "api" scope with "clientsapi" as resource
    var apiScope = await scopeManager.FindByNameAsync("api");
    if (apiScope == null)
    {
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "api",
            DisplayName = "Clients API",
            Resources =
            {
                "clientsapi"  // Resource identifier - token'ın hangi API için olduğunu belirtir
            }
        });
    }
    else
    {
        // Update existing scope to ensure it has the correct resource
        await scopeManager.UpdateAsync(apiScope, new OpenIddictScopeDescriptor
        {
            Name = "api",
            DisplayName = "Clients API",
            Resources =
            {
                "clientsapi"
            }
        });
    }
}

app.Run();
