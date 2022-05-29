package br.jus.pje.analytics.services;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

import br.jus.pje.analytics.models.ResourceLookupJasper;
import br.jus.pje.analytics.models.Superset;
import br.jus.pje.analytics.repositories.AnalyticsRepository;

@Service
public class AnalyticsServiceImpl implements AnalyticsService {

  @Value("${analytics.jasperserver.host}")
  private String jasperServerHost;

  @Value("${analytics.jasperserver.port}")
  private String jasperServerPort;

  @Value("${analytics.jasperserver.domain}")
  private String jasperServerDomain;

  @Value("${analytics.jasperserver.username}")
  private String userName;

  @Value("${analytics.jasperserver.password}")
  private String password;

  private AnalyticsRepository analyticsRepository;

  private ObjectMapper mapper = new XmlMapper();

  private String urlJasperServer;

  @Autowired
  public AnalyticsServiceImpl(final AnalyticsRepository analyticsRepository) {
    this.analyticsRepository = analyticsRepository;
    if (StringUtils.isNotEmpty(jasperServerHost)) {
      montaUrlJasperServer();
    }
  }

  @Override
  public Superset recuperaDashboards() {
    return new Superset(analyticsRepository.getCookie(), analyticsRepository.recuperaDashboards());
  }

  @Override
  public Superset recuperaDashboard(long id) {
    return new Superset(analyticsRepository.getCookie(), analyticsRepository.recuperaDashboard(id));
  }

  @Override
  /**
   * A localizacaoId será usada futuramente quando houver o cadastro de relatorios por localização
   */
  public List<ResourceLookupJasper> recuperaRelatoriosJasper(long localizacaoId) {
    validaJasperserverUrl();
    try {
      String url = urlJasperServer + "/rest_v2/resources?type=reportUnit";
      CloseableHttpResponse response = executaRequisicaoHttp(url);
      if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
        HttpEntity entityResponse = response.getEntity();
        String stringResponse = EntityUtils.toString(entityResponse);
        JavaType type = this.mapper.getTypeFactory().constructCollectionType(List.class,
            ResourceLookupJasper.class);
        return mapper.readValue(stringResponse, type);
      } else {
        throw new RuntimeException("Nenhum relatório cadastrado");
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private CloseableHttpResponse executaRequisicaoHttp(String url) throws IOException {
    HttpGet request = new HttpGet(url);
    CredentialsProvider provider = new BasicCredentialsProvider();
    provider.setCredentials(AuthScope.ANY,
        new UsernamePasswordCredentials(this.userName, this.password));
    CloseableHttpClient httpClient = HttpClientBuilder.create()
        .setDefaultCredentialsProvider(provider).build();
    return httpClient.execute(request);
  }

  @Override
  public byte[] recuperaRelatorioJasper(long localizacaoId, String labelRelatorio) {
    validaJasperserverUrl();
    try {
      List<ResourceLookupJasper> relatorios = this.recuperaRelatoriosJasper(localizacaoId);
      for (ResourceLookupJasper resource : relatorios) {
        if (resource.getLabel().contentEquals(labelRelatorio)) {
          String url = urlJasperServer + "/rest_v2/reports" + resource.getUri() + ".pdf";
          CloseableHttpResponse response = executaRequisicaoHttp(url);
          return IOUtils.toByteArray(response.getEntity().getContent());
        }
      }
      throw new RuntimeException("Nenhum relatório encontrado com o nome " + labelRelatorio);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] recuperaRelatorioJasper(long localizacaoId, String labelRelatorio, int[] localizacoes) {
    validaJasperserverUrl();
    try {
      List<ResourceLookupJasper> relatorios = this.recuperaRelatoriosJasper(localizacaoId);
      for (ResourceLookupJasper resource : relatorios) {
        if (resource.getLabel().contentEquals(labelRelatorio)) {
			StringBuilder url = new StringBuilder(urlJasperServer + "/rest_v2/reports" + resource.getUri() + ".pdf");
			String loc = "?loc="+Arrays.toString(localizacoes)
					.replaceAll("\\[", "")
					.replaceAll("\\]", "")
					.replaceAll(" ", "");
			CloseableHttpResponse response = executaRequisicaoHttp(url+loc);
            return IOUtils.toByteArray(response.getEntity().getContent());
        }
      }
      throw new RuntimeException("Nenhum relatório encontrado com o nome " + labelRelatorio);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void validaJasperserverUrl() {
    if (StringUtils.isBlank(this.urlJasperServer)
        && StringUtils.isNotBlank(this.jasperServerHost)) {
      montaUrlJasperServer();
    } else if (StringUtils.isBlank(this.jasperServerHost)) {
      throw new RuntimeException("Configurações do Jasper Server estão faltando");
    }
  }

  private void montaUrlJasperServer() {
    this.urlJasperServer = "http://" + jasperServerHost + ":" + jasperServerPort + "/"
        + jasperServerDomain;
  }

}
