
using Microsoft.Identity.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using PartnerAdminLinkTool.Core.Models;

namespace PartnerAdminLinkTool.Core.Services
{

    /// <summary>
    /// Implementation of authentication service using Microsoft Authentication Library (MSAL).
    /// 
    /// For beginners: This class handles signing users in and out, and managing access tokens
    /// that we need to call Azure Management APIs. MSAL handles all the
    /// complex OAuth flows for us.
    /// </summary>
    public class AuthenticationService : IAuthenticationService
    {

        /// <summary>
        /// Get an access token for Azure Management API for a specific tenant
        /// </summary>
        public async Task<TokenAcquisitionResult> GetAzureManagementAccessTokenAsync(string tenantId)
        {
            return await GetAzureManagementAccessTokenAsync(tenantId, true);
        }

        /// <summary>
        /// Get an access token for Azure Management API for a specific tenant with control over automatic interactive authentication.
        /// </summary>
        public async Task<TokenAcquisitionResult> GetAzureManagementAccessTokenAsync(string tenantId, bool allowInteractiveAuth)
        {
            try
            {
                if (_msalClient == null || !_currentState.IsAuthenticated)
                {
                    return await Task.FromResult(TokenAcquisitionResult.Failure("not_authenticated", "User is not authenticated."));
                }

                var accounts = await _msalClient.GetAccountsAsync();
                if (!accounts.Any())
                {
                    return await Task.FromResult(TokenAcquisitionResult.Failure("no_accounts", "No accounts found in MSAL cache."));
                }

                try
                {
                    var result = await _msalClient.AcquireTokenSilent(_azureScopes, accounts.FirstOrDefault())
                        .WithTenantId(tenantId)
                        .ExecuteAsync();
                    return await Task.FromResult(TokenAcquisitionResult.Success(result.AccessToken));
                }
                catch (MsalUiRequiredException uiEx)
                {
                    // Parse error code for actionable feedback
                    var errorCode = uiEx.ErrorCode?.ToLowerInvariant();
                    var message = uiEx.Message;
                    if (message.Contains("AADSTS65001") || errorCode == "consent_required")
                    {
                        var consentUrl = GetAdminConsentUrl();
                        _logger.LogWarning("Consent required for tenant {TenantId}. Admin must grant consent using: {ConsentUrl}", tenantId, consentUrl);
                        return await Task.FromResult(TokenAcquisitionResult.Failure("consent_required", $"Consent required for tenant {tenantId}. Admin must grant consent.", consentUrl));
                    }
                    else if (message.Contains("AADSTS50079") || message.Contains("AADSTS50076") || errorCode == "mfa_required" || message.Contains("multi-factor authentication"))
                    {
                        if (allowInteractiveAuth)
                        {
                            _logger.LogWarning("MFA required for tenant {TenantId}. Attempting interactive authentication.", tenantId);
                            // Automatically attempt interactive authentication for MFA
                            try
                            {
                                var interactiveResult = await _msalClient.AcquireTokenInteractive(_azureScopes)
                                    .WithTenantId(tenantId)
                                    .WithPrompt(Prompt.SelectAccount)
                                    .ExecuteAsync();
                                _logger.LogInformation("Interactive MFA authentication successful for tenant {TenantId}", tenantId);
                                return await Task.FromResult(TokenAcquisitionResult.Success(interactiveResult.AccessToken));
                            }
                            catch (Exception interactiveEx)
                            {
                                _logger.LogError(interactiveEx, "Interactive MFA authentication failed for tenant {TenantId}", tenantId);
                                return await Task.FromResult(TokenAcquisitionResult.Failure("mfa_required", $"MFA required for tenant {tenantId}. Interactive authentication failed: {interactiveEx.Message}"));
                            }
                        }
                        else
                        {
                            _logger.LogDebug("MFA required for tenant {TenantId}. Interactive authentication disabled - returning failure for user handling.", tenantId);
                            return await Task.FromResult(TokenAcquisitionResult.Failure("mfa_required", $"MFA required for tenant {tenantId}."));
                        }
                    }
                    else if (message.Contains("AADSTS50158") || errorCode == "basic_action")
                    {
                        if (allowInteractiveAuth)
                        {
                            _logger.LogWarning("External security challenge not satisfied for tenant {TenantId}. Attempting interactive authentication.", tenantId);
                            // Automatically attempt interactive authentication for external security challenge
                            try
                            {
                                var interactiveResult = await _msalClient.AcquireTokenInteractive(_azureScopes)
                                    .WithTenantId(tenantId)
                                    .WithPrompt(Prompt.SelectAccount)
                                    .ExecuteAsync();
                                _logger.LogInformation("Interactive authentication successful for external security challenge on tenant {TenantId}", tenantId);
                                return await Task.FromResult(TokenAcquisitionResult.Success(interactiveResult.AccessToken));
                            }
                            catch (Exception interactiveEx)
                            {
                                _logger.LogError(interactiveEx, "Interactive authentication failed for external security challenge on tenant {TenantId}", tenantId);
                                return await Task.FromResult(TokenAcquisitionResult.Failure("basic_action", $"External security challenge not satisfied for tenant {tenantId}. Interactive authentication failed: {interactiveEx.Message}"));
                            }
                        }
                        else
                        {
                            _logger.LogDebug("External security challenge for tenant {TenantId}. Interactive authentication disabled - returning failure for user handling.", tenantId);
                            return await Task.FromResult(TokenAcquisitionResult.Failure("basic_action", $"External security challenge not satisfied for tenant {tenantId}. User must complete additional authentication."));
                        }
                    }
                    else
                    {
                        if (allowInteractiveAuth)
                        {
                            _logger.LogWarning(uiEx, "Silent token acquisition failed for tenant {TenantId}. Attempting interactive authentication.", tenantId);
                            // For any other UI required exception, attempt interactive authentication
                            try
                            {
                                var interactiveResult = await _msalClient.AcquireTokenInteractive(_azureScopes)
                                    .WithTenantId(tenantId)
                                    .WithPrompt(Prompt.SelectAccount)
                                    .ExecuteAsync();
                                _logger.LogInformation("Interactive authentication successful for tenant {TenantId}", tenantId);
                                return await Task.FromResult(TokenAcquisitionResult.Success(interactiveResult.AccessToken));
                            }
                            catch (Exception interactiveEx)
                            {
                                _logger.LogError(interactiveEx, "Interactive authentication failed for tenant {TenantId}", tenantId);
                                return await Task.FromResult(TokenAcquisitionResult.Failure("ui_required", $"Silent token acquisition failed for tenant {tenantId}: {uiEx.Message}. Interactive authentication also failed: {interactiveEx.Message}"));
                            }
                        }
                        else
                        {
                            _logger.LogDebug("UI required for tenant {TenantId}. Interactive authentication disabled - returning failure for user handling.", tenantId);
                            return await Task.FromResult(TokenAcquisitionResult.Failure("ui_required", $"Silent token acquisition failed for tenant {tenantId}: {uiEx.Message}"));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get access token for Azure Management API for tenant {TenantId}", tenantId);
                return await Task.FromResult(TokenAcquisitionResult.Failure("exception", $"Failed to get access token for tenant {tenantId}: {ex.Message}"));
            }
        }

        /// <summary>
        /// Get the admin consent URL for this application.
        /// </summary>
        public string GetAdminConsentUrl()
        {
            var clientId = _configuration["Authentication:ClientId"] ?? "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
            return $"https://login.microsoftonline.com/common/adminconsent?client_id={clientId}";
        }
        private readonly ILogger<AuthenticationService> _logger;
        private readonly IConfiguration _configuration;
        private IPublicClientApplication? _msalClient;
        private AuthenticationState _currentState = AuthenticationState.Unauthenticated;

        // Azure Management API scopes (Microsoft Graph removed to avoid consent issues)
        private readonly string[] _azureScopes = { "https://management.azure.com/user_impersonation" };

        public event EventHandler<AuthenticationState>? AuthenticationStateChanged;
        public AuthenticationState CurrentState => _currentState;

        public AuthenticationService(ILogger<AuthenticationService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;

            InitializeMsalClient();
        }

        /// <summary>
        /// Initialize the MSAL client with configuration
        /// </summary>
        private void InitializeMsalClient()
        {
            try
            {
                // Get configuration values (these can be set in appsettings.json)
                var clientId = _configuration["Authentication:ClientId"] ?? "04b07795-8ddb-461a-bbee-02f9e1bf7b46"; // Azure CLI client ID
                var authority = _configuration["Authentication:Authority"] ?? "https://login.microsoftonline.com/organizations";
                var redirectUri = _configuration["Authentication:RedirectUri"] ?? "http://localhost";

                _msalClient = PublicClientApplicationBuilder
                    .Create(clientId)
                    .WithAuthority(authority)
                    .WithRedirectUri(redirectUri)
                    .WithLogging((level, message, containsPii) =>
                    {
                        _logger.LogDebug("MSAL {Level}: {Message}", level, message);
                    }, Microsoft.Identity.Client.LogLevel.Info, enablePiiLogging: false, enableDefaultPlatformLogging: true)
                    .Build();

                _logger.LogInformation("MSAL client initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize MSAL client");
                throw;
            }
        }

        /// <summary>
        /// Sign in using interactive authentication (opens browser window)
        /// </summary>
        public async Task<AuthenticationState> SignInInteractiveAsync()
        {
            try
            {
                _logger.LogInformation("Starting interactive sign-in");

                if (_msalClient == null)
                {
                    throw new InvalidOperationException("MSAL client not initialized");
                }

                // Try to get accounts from cache first
                var accounts = await _msalClient.GetAccountsAsync();
                AuthenticationResult result;

                if (accounts.Any())
                {
                    // Try silent authentication first
                    try
                    {
                        result = await _msalClient.AcquireTokenSilent(_azureScopes, accounts.FirstOrDefault())
                            .ExecuteAsync();
                        _logger.LogInformation("Silent authentication successful");
                    }
                    catch (MsalUiRequiredException)
                    {
                        // Fall back to interactive authentication
                        result = await _msalClient.AcquireTokenInteractive(_azureScopes)
                            .ExecuteAsync();
                        _logger.LogInformation("Interactive authentication successful");
                    }
                }
                else
                {
                    // No cached accounts, use interactive authentication
                    result = await _msalClient.AcquireTokenInteractive(_azureScopes)
                        .ExecuteAsync();
                    _logger.LogInformation("Interactive authentication successful");
                }

                await UpdateAuthenticationStateAsync(result);
                return _currentState;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Interactive sign-in failed");
                _currentState = AuthenticationState.Unauthenticated;
                AuthenticationStateChanged?.Invoke(this, _currentState);
                return _currentState;
            }
        }

        /// <summary>
        /// Sign in using device code flow (for machines without browsers)
        /// </summary>
        public async Task<AuthenticationState> SignInWithDeviceCodeAsync(Func<string, string, Task> deviceCodeCallback)
        {
            try
            {
                _logger.LogInformation("Starting device code sign-in");

                if (_msalClient == null)
                {
                    throw new InvalidOperationException("MSAL client not initialized");
                }

                var result = await _msalClient.AcquireTokenWithDeviceCode(_azureScopes, async deviceCodeResult =>
                {
                    // Call the provided callback to display device code to user
                    await deviceCodeCallback(deviceCodeResult.UserCode, deviceCodeResult.VerificationUrl);
                    _logger.LogInformation("Device code displayed to user: {UserCode}", deviceCodeResult.UserCode);
                }).ExecuteAsync();

                _logger.LogInformation("Device code authentication successful");
                await UpdateAuthenticationStateAsync(result);
                return _currentState;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Device code sign-in failed");
                _currentState = AuthenticationState.Unauthenticated;
                AuthenticationStateChanged?.Invoke(this, _currentState);
                return _currentState;
            }
        }

        /// <summary>
        /// Try to sign in silently using cached tokens
        /// </summary>
        public async Task<AuthenticationState> TrySignInSilentlyAsync()
        {
            try
            {
                _logger.LogInformation("Attempting silent sign-in");

                if (_msalClient == null)
                {
                    throw new InvalidOperationException("MSAL client not initialized");
                }

                var accounts = await _msalClient.GetAccountsAsync();
                if (!accounts.Any())
                {
                    _logger.LogInformation("No cached accounts found");
                    return _currentState;
                }

                var result = await _msalClient.AcquireTokenSilent(_azureScopes, accounts.FirstOrDefault())
                    .ExecuteAsync();

                _logger.LogInformation("Silent sign-in successful");
                await UpdateAuthenticationStateAsync(result);
                return _currentState;
            }
            catch (MsalUiRequiredException)
            {
                _logger.LogInformation("Silent sign-in requires user interaction");
                return _currentState;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Silent sign-in failed");
                return _currentState;
            }
        }

        /// <summary>
        /// Sign out the current user
        /// </summary>
        public async Task SignOutAsync()
        {
            try
            {
                _logger.LogInformation("Signing out user");

                if (_msalClient == null)
                {
                    return;
                }

                var accounts = await _msalClient.GetAccountsAsync();
                foreach (var account in accounts)
                {
                    await _msalClient.RemoveAsync(account);
                }

                _currentState = AuthenticationState.Unauthenticated;
                AuthenticationStateChanged?.Invoke(this, _currentState);
                _logger.LogInformation("User signed out successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Sign out failed");
            }
        }

        /// <summary>
        /// Get an access token for Azure Management API
        /// </summary>
        public async Task<string?> GetAzureManagementAccessTokenAsync()
        {
            return await GetAccessTokenAsync(_azureScopes);
        }

        /// <summary>
        /// Perform interactive authentication for Azure Management API for a specific tenant
        /// </summary>
        public async Task<TokenAcquisitionResult> InteractiveAzureManagementAuthAsync(string tenantId)
        {
            try
            {
                if (_msalClient == null)
                    throw new InvalidOperationException("MSAL client not initialized");

                var result = await _msalClient.AcquireTokenInteractive(_azureScopes)
                    .WithTenantId(tenantId)
                    .WithPrompt(Prompt.SelectAccount)
                    .ExecuteAsync();
                
                _logger.LogInformation("Interactive authentication successful for tenant {TenantId}", tenantId);
                return TokenAcquisitionResult.Success(result.AccessToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Interactive Azure Management API authentication failed for tenant {TenantId}", tenantId);
                return TokenAcquisitionResult.Failure("interactive_failed", $"Interactive authentication failed for tenant {tenantId}: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle MFA requirement for a specific tenant with user-friendly prompts
        /// </summary>
        public async Task<TokenAcquisitionResult> HandleMfaRequiredAsync(string tenantId, string? userMessage = null)
        {
            try
            {
                _logger.LogInformation("Handling MFA requirement for tenant {TenantId}", tenantId);
                
                if (_msalClient == null)
                    throw new InvalidOperationException("MSAL client not initialized");

                // Attempt interactive authentication with clear MFA prompt
                var result = await _msalClient.AcquireTokenInteractive(_azureScopes)
                    .WithTenantId(tenantId)
                    .WithPrompt(Prompt.ForceLogin) // Force login to ensure MFA is triggered
                    .WithExtraQueryParameters(new Dictionary<string, string> 
                    { 
                        // These parameters help ensure MFA is properly triggered
                        { "domain_hint", "organizations" },
                        { "login_hint", _currentState.UserPrincipalName ?? "" }
                    })
                    .ExecuteAsync();
                
                _logger.LogInformation("MFA authentication successful for tenant {TenantId}", tenantId);
                return TokenAcquisitionResult.Success(result.AccessToken);
            }
            catch (MsalUiRequiredException uiEx)
            {
                _logger.LogError(uiEx, "MFA authentication still requires UI for tenant {TenantId}", tenantId);
                return TokenAcquisitionResult.Failure("mfa_ui_required", $"MFA authentication failed for tenant {tenantId}. Additional UI interaction required: {uiEx.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MFA authentication failed for tenant {TenantId}", tenantId);
                return TokenAcquisitionResult.Failure("mfa_failed", $"MFA authentication failed for tenant {tenantId}: {ex.Message}");
            }
        }

        /// <summary>
        /// Get an access token for the specified scopes
        /// </summary>
        private async Task<string?> GetAccessTokenAsync(string[] scopes)
        {
            try
            {
                if (_msalClient == null || !_currentState.IsAuthenticated)
                {
                    return null;
                }

                var accounts = await _msalClient.GetAccountsAsync();
                if (!accounts.Any())
                {
                    return null;
                }

                try
                {
                    var result = await _msalClient.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                        .ExecuteAsync();
                    return result.AccessToken;
                }
                catch (MsalUiRequiredException uiEx)
                {
                    _logger.LogWarning(uiEx, "Silent token acquisition failed, attempting interactive consent for scopes: {Scopes}", string.Join(", ", scopes));
                    try
                    {
                        var result = await _msalClient.AcquireTokenInteractive(scopes)
                            .ExecuteAsync();
                        return result.AccessToken;
                    }
                    catch (Exception interactiveEx)
                    {
                        _logger.LogError(interactiveEx, "Interactive consent failed for scopes: {Scopes}", string.Join(", ", scopes));
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get access token for scopes: {Scopes}", string.Join(", ", scopes));
                return null;
            }
        }

        /// <summary>
        /// Update the authentication state based on the authentication result
        /// </summary>
        private Task UpdateAuthenticationStateAsync(AuthenticationResult result)
        {
            _currentState = new AuthenticationState
            {
                IsAuthenticated = true,
                UserPrincipalName = result.Account.Username,
                DisplayName = result.Account.Username, // Could be enhanced with Graph call to get display name
                HomeTenantId = result.Account.HomeAccountId?.TenantId,
                LastAuthenticationTime = DateTime.UtcNow,
                TokenExpiresAt = result.ExpiresOn.UtcDateTime
            };

            AuthenticationStateChanged?.Invoke(this, _currentState);
            _logger.LogInformation("Authentication state updated for user: {User}", _currentState.UserPrincipalName);
            return Task.CompletedTask;
        }
    }
}