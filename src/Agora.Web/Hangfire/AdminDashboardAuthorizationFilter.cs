using Hangfire.Annotations;
using Hangfire.Dashboard;

namespace Agora.Web.Hangfire;

public sealed class AdminDashboardAuthorizationFilter : IDashboardAuthorizationFilter
{
    public bool Authorize([NotNull] DashboardContext context)
    {
        var httpContext = context.GetHttpContext();
        var user = httpContext.User;
        return user.Identity?.IsAuthenticated == true && user.IsInRole("admin");
    }
}
