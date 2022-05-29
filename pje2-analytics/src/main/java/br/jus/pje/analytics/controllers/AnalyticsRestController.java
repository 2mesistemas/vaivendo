package br.jus.pje.analytics.controllers;

import java.util.List;

import org.springframework.http.ResponseEntity;

import br.jus.pje.analytics.models.ResourceLookupJasper;
import br.jus.pje.analytics.models.Superset;

public interface AnalyticsRestController {

  public ResponseEntity<Superset> recuperaDashboards();

  public ResponseEntity<List<ResourceLookupJasper>> recuperaRelatoriosJasper(long localizacaoId);

  public ResponseEntity<String> health();
}
