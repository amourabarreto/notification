package com.ead.notification.controller;

import com.ead.notification.dtos.NotificationDto;
import com.ead.notification.models.NotificationModel;
import com.ead.notification.services.NotificationService;
import jdk.jshell.Snippet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Optional;
import java.util.UUID;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserNotificationController {

    @Autowired
    NotificationService notificationService;

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/users/{userId}/notifications")
    public ResponseEntity<Page<NotificationModel>> getAllNotificationsByUser(@PathVariable("userId") UUID userId,
                                                                             @PageableDefault(page = 0, size = 10, sort = "notificationId",
                                                                             direction = Sort.Direction.ASC) Pageable pageable){
         return ResponseEntity.status(HttpStatus.OK).body(notificationService.findAllNotificationsByUser(userId,pageable));
    }

    @PutMapping("/users/{userId}/notifications/{notificationId}")
    public ResponseEntity<Object> update(@PathVariable("userId") UUID userId,
                                  @PathVariable("notificationId") UUID notificationId,
                                  @RequestBody @Valid NotificationDto notificationDto){
        Optional<NotificationModel> notificationModelOptional = notificationService.findaByNotificatioIdAndUserId(notificationId,userId);
        if(notificationModelOptional.isEmpty()){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Notificação não encontrada!");
        }
        notificationModelOptional.get().setNotificationStatus(notificationDto.getNotificationStatus());
        notificationService.save(notificationModelOptional.get());

     return ResponseEntity.status(HttpStatus.OK).body(notificationModelOptional.get());
    }
}
