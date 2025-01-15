export class ChangePasswordRequestDto {
  access_token: string;
  previous_password: string;
  proposed_password: string;
}
