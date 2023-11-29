window.onload = function() {
  window.ui = SwaggerUIBundle({
    url: "./nethsm-api.yaml",
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [
      SwaggerUIBundle.presets.apis,
    ],
    plugins: [
      SwaggerUIBundle.plugins.DownloadUrl
    ],
    showExtensions: true,
  });
};
