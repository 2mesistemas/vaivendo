package br.jus.pje.analytics.services;

import java.util.List;

import br.jus.pje.analytics.models.ResourceLookupJasper;
import br.jus.pje.analytics.models.Superset;

public interface AnalyticsService {

  public Superset recuperaDashboards();

  public Superset recuperaDashboard(long id);

  public List<ResourceLookupJasper> recuperaRelatoriosJasper(long localizacaoId);

  public byte[] recuperaRelatorioJasper(long localizacaoId, String uriRelatorio);

  public byte[] recuperaRelatorioJasper(long localizacaoId, String uriRelatorio, int[] localizacoes);

}
