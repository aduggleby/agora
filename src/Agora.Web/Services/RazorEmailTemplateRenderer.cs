using Agora.Application.Abstractions;
using Agora.Application.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Routing;

namespace Agora.Web.Services;

public sealed class RazorEmailTemplateRenderer(
    IRazorViewEngine razorViewEngine,
    ITempDataProvider tempDataProvider,
    IServiceProvider serviceProvider) : IEmailTemplateRenderer
{
    public async Task<string> RenderDownloadNotificationHtmlAsync(DownloadNotification notification, CancellationToken cancellationToken)
    {
        return await RenderViewAsync("/Pages/Emails/DownloadNotification.cshtml", notification, cancellationToken);
    }

    public async Task<string> RenderAuthEmailHtmlAsync(AuthEmailMessage message, CancellationToken cancellationToken)
    {
        return await RenderViewAsync("/Pages/Emails/AuthMessage.cshtml", message, cancellationToken);
    }

    private async Task<string> RenderViewAsync<TModel>(string viewPath, TModel model, CancellationToken cancellationToken)
    {
        var httpContext = new DefaultHttpContext { RequestServices = serviceProvider };
        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());

        var viewResult = razorViewEngine.GetView(executingFilePath: null, viewPath: viewPath, isMainPage: true);
        if (!viewResult.Success || viewResult.View is null)
        {
            throw new InvalidOperationException($"Unable to locate email template '{viewPath}'.");
        }

        await using var writer = new StringWriter();
        var viewData = new ViewDataDictionary<TModel>(
            new EmptyModelMetadataProvider(),
            new ModelStateDictionary())
        {
            Model = model
        };

        var tempData = new TempDataDictionary(httpContext, tempDataProvider);
        var viewContext = new ViewContext(actionContext, viewResult.View, viewData, tempData, writer, new HtmlHelperOptions());

        await viewResult.View.RenderAsync(viewContext);
        cancellationToken.ThrowIfCancellationRequested();
        return writer.ToString();
    }
}
