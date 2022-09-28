import 'package:equatable/equatable.dart';

class AuthUser extends Equatable {
  const AuthUser({
    required this.id,
    this.email,
    this.name,
    this.emailVerified = false,
  });

  final String id;
  final String? email;
  final String? name;
  final bool emailVerified;

  static const AuthUser empty = AuthUser(id: '');

  bool get isEmpty => this == AuthUser.empty;

  @override
  List<Object?> get props => [
        email,
        id,
        name,
        emailVerified,
      ];
}
