export class ListUsersRequestDto {
  attributes: string[];
  filter: string;
  limit: number;
  pagination_token: string;
}
