package com.user_service.user_service.dtos;

import java.util.List;

public record OrderRecord(Long id, Long userId, String status, List<OrderItemRecord> orderItems) {
}
