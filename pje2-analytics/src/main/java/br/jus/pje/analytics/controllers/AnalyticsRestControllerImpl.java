package br.jus.pje.analytics.controllers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.h2.util.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import br.jus.pje.analytics.models.ResourceLookupJasper;
import br.jus.pje.analytics.models.Superset;
import br.jus.pje.analytics.services.AnalyticsService;

@RestController
@RequestMapping("/analytics")
public class AnalyticsRestControllerImpl implements AnalyticsRestController {

  private AnalyticsService analyticsService;

  @Autowired
  public AnalyticsRestControllerImpl(final AnalyticsService analyticsService) {
    this.analyticsService = analyticsService;
  }

  @Override
  @GetMapping(path = "/dashboards", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<Superset> recuperaDashboards() {
    Superset dashboards = analyticsService.recuperaDashboards();
    HttpHeaders headers = new HttpHeaders();
    headers.add("Set-Cookie", dashboards.getCookie());
    headers.add("Cookie", dashboards.getCookie());
    return new ResponseEntity<>(dashboards, headers, HttpStatus.OK);
  }

  @GetMapping(path = "/dashboards/{dashboardId}")
  public void recuperaDashboard(@PathVariable(required = true) long dashboardId,
      HttpServletResponse response) throws IOException {
    Superset superset = analyticsService.recuperaDashboard(dashboardId);
    if (!superset.getDashboards().isEmpty()) {
      response.setContentType(MediaType.TEXT_HTML_VALUE);
      IOUtils.copy(new ByteArrayInputStream(superset.getDashboards().get(0).getContent()),
          response.getOutputStream());
    }
  }

  @GetMapping(path = "/localizacoes/{localizacaoId}/relatorios",
      produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<List<ResourceLookupJasper>> recuperaRelatoriosJasper(
      @PathVariable(required = true) long localizacaoId) {
    List<ResourceLookupJasper> relatorios = analyticsService
        .recuperaRelatoriosJasper(localizacaoId);
    HttpHeaders headers = new HttpHeaders();
    return new ResponseEntity<>(relatorios, headers, HttpStatus.OK);
  }

  @GetMapping(path = "/localizacoes/{localizacaoId}/relatorios/{uriRelatorio}",
      produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  @ResponseBody
  public byte[] recuperaRelatorio(@PathVariable(required = true) long localizacaoId,
      @PathVariable(required = true) String uriRelatorio) {
    return analyticsService.recuperaRelatorioJasper(localizacaoId, uriRelatorio);
  }

  
	@PostMapping(path = "/localizacoes/{localizacaoId}/relatorios/{uriRelatorio}", 
			produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	@ResponseBody
	public byte[] recuperaRelatorio(@PathVariable(required = true) long localizacaoId,
			@PathVariable(required = true) String uriRelatorio, @RequestBody int[] localizacoes) {
		return analyticsService.recuperaRelatorioJasper(localizacaoId, uriRelatorio, localizacoes);
	}
  
  @GetMapping(value = "/health", produces = { "application/json" })
  public ResponseEntity<String> health() {
    return new ResponseEntity<>("status: UP", HttpStatus.OK);
  }
}
