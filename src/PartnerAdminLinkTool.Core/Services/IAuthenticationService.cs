using PartnerAdminLinkTool.Core.Models;

namespace PartnerAdminLinkTool.Core.Services;

/// <summary>
/// Interface for authentication services.
/// 
/// For beginners: An interface is like a contract - it defines what methods
/// a class must implement, but not how. This allows us to easily swap out
/// different authentication implementations for testing or different scenarios.
/// </summary>
public interface IAuthenticationService
{
    /// <summary>
    /// Event fired when authentication state changes
    /// </summary>
    event EventHandler<AuthenticationState>? AuthenticationStateChanged;

    /// <summary>
    /// Get the current authentication state
    /// </summary>
    AuthenticationState CurrentState { get; }

    /// <summary>
    /// Sign in using interactive authentication (opens a browser window)
    /// </summary>
    /// <returns>Authentication state after sign-in attempt</returns>
    Task<AuthenticationState> SignInInteractiveAsync();

    /// <summary>
    /// Sign in using device code flow (for machines without browsers)
    /// </summary>
    /// <param name="deviceCodeCallback">Callback to display device code to user</param>
    /// <returns>Authentication state after sign-in attempt</returns>
    Task<AuthenticationState> SignInWithDeviceCodeAsync(Func<string, string, Task> deviceCodeCallback);

    /// <summary>
    /// Sign out the current user
    /// </summary>
    Task SignOutAsync();

    /// <summary>
    /// Try to sign in silently using cached tokens
    /// </summary>
    /// <returns>Authentication state after silent sign-in attempt</returns>
    Task<AuthenticationState> TrySignInSilentlyAsync();

    /// <summary>
    /// Get an access token for Azure Management API (default tenant)
    /// </summary>
    /// <returns>Access token or null if not authenticated</returns>
    Task<string?> GetAzureManagementAccessTokenAsync();

    /// <summary>
    /// Get an access token for Azure Management API for a specific tenant, with actionable error info.
    /// </summary>
    /// <param name="tenantId">Tenant ID to acquire token for</param>
    /// <returns>Result containing access token or actionable error info</returns>
    Task<TokenAcquisitionResult> GetAzureManagementAccessTokenAsync(string tenantId);

    /// <summary>
    /// Get an access token for Azure Management API for a specific tenant with control over automatic interactive authentication.
    /// </summary>
    /// <param name="tenantId">Tenant ID to acquire token for</param>
    /// <param name="allowInteractiveAuth">Whether to automatically attempt interactive authentication for MFA</param>
    /// <returns>Result containing access token or actionable error info</returns>
    Task<TokenAcquisitionResult> GetAzureManagementAccessTokenAsync(string tenantId, bool allowInteractiveAuth);

    /// <summary>
    /// Perform interactive authentication for Azure Management API for a specific tenant
    /// </summary>
    /// <param name="tenantId">Tenant ID to acquire token for</param>
    /// <returns>Result containing access token or error info</returns>
    Task<TokenAcquisitionResult> InteractiveAzureManagementAuthAsync(string tenantId);

    /// <summary>
    /// Handle MFA requirement for a specific tenant with user-friendly prompts
    /// </summary>
    /// <param name="tenantId">Tenant ID to acquire token for</param>
    /// <param name="userMessage">Optional message to display to user</param>
    /// <returns>Result containing access token or error info</returns>
    Task<TokenAcquisitionResult> HandleMfaRequiredAsync(string tenantId, string? userMessage = null);
}