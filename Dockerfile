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
WORKDIR /app

ENV ASPNETCORE_URLS=http://0.0.0.0:18080
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ConnectionStrings__Default="Data Source=/app/data/uploads/agora.db"
ENV Agora__StorageRoot=/app/data/uploads
ENV Serilog__WriteTo__0__Args__path=/app/data/logs/agora-.log
ENV Email__Resend__ApiUrl=https://api.resend.com
ENV Email__Resend__ApiToken=
ENV Email__Resend__FromAddress=no-reply@example.com

VOLUME ["/app/data"]
EXPOSE 18080

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Agora.Web.dll"]
