# 使用官方的 .NET 8 运行时镜像
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# 使用 .NET 8 SDK 镜像进行构建
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["SecureAuth.Api/SecureAuth.Api.csproj", "SecureAuth.Api/"]
RUN dotnet restore "SecureAuth.Api/SecureAuth.Api.csproj"
COPY . .
WORKDIR "/src/SecureAuth.Api"
RUN dotnet build "SecureAuth.Api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "SecureAuth.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# 设置环境变量
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:80

ENTRYPOINT ["dotnet", "SecureAuth.Api.dll"]