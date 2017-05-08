FROM microsoft/dotnet:latest
COPY . ./Edorator.Security
WORKDIR ./Edorator.Security
RUN dotnet restore
RUN dotnet publish --framework netcoreapp1.1 -o out
EXPOSE 5001
ENTRYPOINT dotnet ./out/Edorator.Security.dll