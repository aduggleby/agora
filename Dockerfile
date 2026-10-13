FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Agora.slnx ./
COPY src/Agora.Web/Agora.Web.csproj src/Agora.Web/
COPY src/Agora.Application/Agora.Application.csproj src/Agora.Application/
COPY src/Agora.Domain/Agora.Domain.csproj src/Agora.Domain/
COPY src/Agora.Infrastructure/Agora.Infrastructure.csproj src/Agora.Infrastructure/
COPY tests/Agora.Application.Tests/Agora.Application.Tests.csproj tests/Agora.Application.Tests/

RUN dotnet restore Agora.slnx

COPY . .
RUN dotnet publish src/Agora.Web/Agora.Web.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
# Image generation uses SkiaSharp (NativeAssets.Linux.NoDependencies: links only glibc, libstdc++ and libgcc_s, no
# fontconfig; fonts come from /app/Fonts) and PDFium, both already shipped as managed-package native assets. No apt
# packages are needed on this base image.
WORKDIR /app

ENV ASPNETCORE_URLS=http://0.0.0.0:18080
ENV ASPNETCORE_ENVIRONMENT=Production
ENV Agora__StorageRoot=/app/data/uploads
ENV Agora__Logging__File__Path=/app/data/logs
ENV DataProtection__KeysPath=/app/data/keys
ENV Email__Resend__ApiUrl=https://api.resend.com
ENV Email__Resend__ApiToken=
ENV Email__Resend__FromAddress=no-reply@example.com

VOLUME ["/app/data"]
EXPOSE 18080

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Agora.Web.dll"]
