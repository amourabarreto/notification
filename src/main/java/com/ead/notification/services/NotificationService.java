package com.ead.notification.services;

import com.ead.notification.models.NotificationModel;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;
import java.util.UUID;

public interface NotificationService {
    NotificationModel save(NotificationModel notificationModel);

    Page<NotificationModel> findAllNotificationsByUser(UUID userId, Pageable pageable);

    Optional<NotificationModel> findaByNotificatioIdAndUserId(UUID notificationId, UUID userId);
}
