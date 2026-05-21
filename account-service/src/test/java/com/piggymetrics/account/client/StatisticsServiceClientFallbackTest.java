package com.piggymetrics.account.client;

import com.piggymetrics.account.domain.Account;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

/**
 * @author cdov
 */
@SpringBootTest(properties = {
        "spring.cloud.openfeign.circuitbreaker.enabled=true"
})
@ExtendWith(OutputCaptureExtension.class)
public class StatisticsServiceClientFallbackTest {
    @Autowired
    private StatisticsServiceClient statisticsServiceClient;

    @MockBean
    private OAuth2AuthorizedClientManager authorizedClientManager;

    @Test
    public void testUpdateStatisticsWithFailFallback(CapturedOutput capturedOutput){
        statisticsServiceClient.updateStatistics("test", new Account());

        assertThat(capturedOutput.getAll(), containsString("Error during update statistics for account: test"));

    }

}
