package br.jus.pje.analytics.repositories;

import java.util.List;

import br.jus.pje.analytics.models.Dashboard;

public interface AnalyticsRepository {

  public List<Dashboard> recuperaDashboards();

  public Dashboard recuperaDashboard(long dashboardId);

  public String getCookie();
}
