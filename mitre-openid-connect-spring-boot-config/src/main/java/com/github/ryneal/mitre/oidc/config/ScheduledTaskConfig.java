package com.github.ryneal.mitre.oidc.config;

import com.github.ryneal.mitre.oidc.config.ScheduledTaskConfig.SchedulingEnabledCondition;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

@Configuration
@EnableScheduling
@Conditional(SchedulingEnabledCondition.class)
@ConfigurationProperties(prefix = "openid.connect.scheduling")
public class ScheduledTaskConfig implements SchedulingConfigurer {

    private final DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService;

    private final ApprovedSiteService approvedSiteService;

    private final DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService;

    public ScheduledTaskConfig(DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService,
                               ApprovedSiteService approvedSiteService,
                               DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService) {
        this.defaultOAuth2ProviderTokenService = defaultOAuth2ProviderTokenService;
        this.approvedSiteService = approvedSiteService;
        this.defaultOAuth2AuthorizationCodeService = defaultOAuth2AuthorizationCodeService;
    }

    @Bean(destroyMethod = "shutdown")
    public Executor taskScheduler() {
        return Executors.newScheduledThreadPool(5);
    }

    @Scheduled(fixedDelayString = "${openid.connect.scheduling.tasks.clearExpiredTokens.fixedDelay:30000}",
            initialDelayString = "${openid.connect.scheduling.tasks.clearExpiredTokens.initialDelay:60000}")
    public void clearExpiredTokens() {
        defaultOAuth2ProviderTokenService.clearExpiredTokens();
    }

    @Scheduled(fixedDelayString = "${openid.connect.scheduling.tasks.clearExpiredSites.fixedDelay:30000}",
            initialDelayString = "${openid.connect.scheduling.tasks.clearExpiredSites.initialDelay:60000}")
    public void clearExpiredSites() {
        approvedSiteService.clearExpiredSites();
    }

    @Scheduled(fixedDelayString = "${openid.connect.scheduling.tasks.clearExpiredAuthorizationCodes.fixedDelay:30000}",
            initialDelayString = "${openid.connect.scheduling.tasks.clearExpiredAuthorizationCodes.initialDelay:60000}")
    public void clearExpiredAuthorizationCodes() {
        defaultOAuth2AuthorizationCodeService.clearExpiredAuthorizationCodes();
    }

    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        taskRegistrar.setScheduler(taskScheduler());
    }

    protected static class SchedulingEnabledCondition extends SpringBootCondition implements ConfigurationCondition {

        @Override
        public ConfigurationPhase getConfigurationPhase() {
            return ConfigurationPhase.REGISTER_BEAN;
        }

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Environment environment = context.getEnvironment();
            String enabled = environment.getProperty("openid.connect.scheduling.enabled");
            if (enabled != null && Boolean.valueOf(enabled).equals(false)) {
                return ConditionOutcome.noMatch("Task Scheduling is disabled");
            }
            return ConditionOutcome.match("Task Scheduling is enabled");
        }

    }

}