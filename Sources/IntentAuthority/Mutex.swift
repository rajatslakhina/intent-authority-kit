//
//  Mutex.swift
//  IntentAuthority
//
//  A minimal portable lock so `ManualClock` can be `Sendable` without pulling in
//  Foundation or platform-specific synchronisation. The broker itself uses an
//  actor; this exists only for the small number of value holders that must be
//  usable from synchronous, non-isolated contexts.
//

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class Mutex: @unchecked Sendable {
    private let storage: UnsafeMutablePointer<pthread_mutex_t>

    init() {
        storage = UnsafeMutablePointer<pthread_mutex_t>.allocate(capacity: 1)
        storage.initialize(to: pthread_mutex_t())
        // `pthread_mutex_init` with a nil attribute pointer cannot fail for a
        // default mutex on either supported platform.
        pthread_mutex_init(storage, nil)
    }

    deinit {
        pthread_mutex_destroy(storage)
        storage.deinitialize(count: 1)
        storage.deallocate()
    }

    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        pthread_mutex_lock(storage)
        defer { pthread_mutex_unlock(storage) }
        return try body()
    }
}
