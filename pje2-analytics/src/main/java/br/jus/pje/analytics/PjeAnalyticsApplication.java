package br.jus.pje.analytics;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@SpringBootApplication
public class PjeAnalyticsApplication {

  @Value("${spring.application.name}")
  private String appName;

  public static void main(String[] args) {
    SpringApplication.run(PjeAnalyticsApplication.class, args);
  }

}
