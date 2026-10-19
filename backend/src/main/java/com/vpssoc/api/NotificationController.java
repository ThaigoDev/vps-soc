package com.vpssoc.api;

import com.vpssoc.notification.TelegramNotifier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Alert channel status and test, so the dashboard can show whether off-screen alerts work. */
@RestController
@RequestMapping("/api/v1/notifications")
public class NotificationController {

    private final TelegramNotifier telegram;

    public NotificationController(TelegramNotifier telegram) {
        this.telegram = telegram;
    }

    @GetMapping("/telegram")
    public Map<String, Object> telegramStatus() {
        return Map.of("enabled", telegram.enabled(), "minSeverity", telegram.minSeverity());
    }

    @PostMapping("/telegram/test")
    public Map<String, String> telegramTest() {
        return Map.of("result", telegram.sendTest().name());
    }
}
