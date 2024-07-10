package org.wildfly.test.integration.elytron.oidc.client;

import mockit.integration.junit4.JMockit;
import org.jboss.arquillian.junit.Arquillian;
import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.InitializationError;

public class ArquillianJMockitRunner extends Runner {

    private final Runner arquillianRunner;
    private final Runner jmockitRunner;

    public ArquillianJMockitRunner(Class<?> testClass) throws InitializationError {
        arquillianRunner = new Arquillian(testClass);
        jmockitRunner = new JMockit(testClass);
    }

    @Override
    public void run(RunNotifier notifier) {
        arquillianRunner.run(notifier);
        jmockitRunner.run(notifier);
    }

    @Override
    public Description getDescription() {
        Description arquillianDescription = arquillianRunner.getDescription();
        Description jmockitDescription = jmockitRunner.getDescription();

        // Combine descriptions, assuming Arquillian as the main description
        for (Description child : jmockitDescription.getChildren()) {
            arquillianDescription.addChild(child);
        }

        return arquillianDescription;
    }
}